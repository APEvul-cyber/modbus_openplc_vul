# Vulnerability Report: OpenPLC v3 ModbusTCP Unrestricted Register Write via FC=06

## Metadata

| Field | Value |
|-------|-------|
| **Vendor** | OpenPLC Project (Thiago Alves) |
| **Product** | OpenPLC Runtime v3 |
| **Product URL** | https://github.com/thiagoralves/OpenPLC_v3 |
| **Affected Version** | OpenPLC_v3 master branch (all versions using `webserver/core/modbus.cpp`) |
| **Tested Version** | OpenPLC_v3 (downloaded 2026-01, Docker build on debian:trixie) |
| **CWE** | CWE-306: Missing Authentication for Critical Function |

---

## 1. Summary

An unrestricted write vulnerability exists in the Modbus TCP server functionality of OpenPLC_v3. The `WriteRegister()` function in `webserver/core/modbus.cpp` accepts FC=06 (Write Single Register) requests from any unauthenticated network client without performing any access control check on the target register address or value. An attacker who can reach TCP port 502 on the OpenPLC host can overwrite **any** holding register (addresses 0–8191) in a single 12-byte Modbus request.

FC=06 writes to **four distinct PLC memory regions** through `writeToRegisterWithoutLocking()`:

| Address Range | Memory Target | IEC 61131-3 Variable | Physical Meaning |
|--------------|--------------|---------------------|------------------|
| 0–1023 | `int_output[]` | `%QW` (analog outputs) | **Directly drives physical actuators** (valves, motors, heaters) |
| 1024–2047 | `int_memory[]` | `%MW` (16-bit memory) | Internal PLC state (setpoints, counters, flags) |
| 2048–4095 | `dint_memory[]` | `%MD` (32-bit memory) | 32-bit integers (accumulated values, timers) |
| 4096–8191 | `lint_memory[]` | `%ML` (64-bit memory) | 64-bit integers (high-precision counters) |

OpenPLC provides **no mechanism** — configurable or hardcoded — to restrict which registers can be written remotely. FC=06 is particularly dangerous because its 12-byte request is the **smallest possible Modbus write message**, making it harder to distinguish from legitimate SCADA polling traffic.

---

## 2. Confirmed Vulnerable Version

OpenPLC Runtime v3, downloaded from `https://github.com/thiagoralves/OpenPLC_v3` (master branch).

The vulnerable code in `WriteRegister()` (line 635) and `writeToRegisterWithoutLocking()` (line 575) has remained structurally unchanged across all known versions of OpenPLC v3.

---

## 3. Technical Details

OpenPLC is an open-source programmable logic controller designed for automation and ICS security research. It supports Modbus TCP on TCP/502 and EtherNet/IP. The runtime can be deployed on Linux, Windows, and embedded platforms. OpenPLC is cited in numerous academic ICS security papers and has been the subject of 8+ CVEs assigned by Cisco Talos and CISA since 2024.

### 3.1 Vulnerability Root Cause

The vulnerability exists in the processing path for Modbus Function Code 06 (Write Single Register). The code performs no authentication, authorization, or access control at any point in the request processing chain. The complete call path is:

**`server.cpp:startServer()` → `server.cpp:handleConnections()` → `server.cpp:processMessage()` → `modbus.cpp:processModbusMessage()` → `modbus.cpp:WriteRegister()` → `modbus.cpp:writeToRegisterWithoutLocking()`**

### 3.2 Code Flow Analysis

When a Modbus TCP client connects to port 502, `startServer()` accepts the connection and spawns a handler thread. The handler calls `processMessage()` ([1]), which dispatches to `processModbusMessage()`:

```c
// server.cpp — processMessage() (line 181)
void processMessage(unsigned char *buffer, int bufferSize, int client_fd, int protocol_type)
{
    int messageSize = 0;
    if (protocol_type == MODBUS_PROTOCOL)
    {
        messageSize = processModbusMessage(buffer, bufferSize);  // [1]
    }
    while (messageSize > 0)
    {
        ssize_t bytesWritten = write(client_fd, buffer, messageSize);  // [2]
        // ...
    }
}
```

Inside `processModbusMessage()`, the function code at `buffer[7]` is checked. **No authentication or client identity check occurs** ([3]):

```c
// modbus.cpp — processModbusMessage() (line 1107)
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    // ...

    // NOTE: No authentication, no client identity check, no IP filtering

    else if(buffer[7] == MB_FC_WRITE_REGISTER)  // FC=06 (0x06)
    {
        WriteRegister(buffer, bufferSize);       // [3] — no auth check before dispatch
    }
    // ...
}
```

The `WriteRegister()` function (line 635) extracts the Register Address from `buffer[8..9]` ([4]) and the Register Value from `buffer[10..11]` ([5]), then passes both directly to `writeToRegisterWithoutLocking()`:

```c
// modbus.cpp — WriteRegister() (line 635)
void WriteRegister(unsigned char *buffer, int bufferSize)
{
    int Start;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);          // [4] Register Address — attacker-controlled

    pthread_mutex_lock(&bufferLock);
    mb_error = writeToRegisterWithoutLocking(     // [5] Direct write, no auth
        Start,
        word(buffer[10], buffer[11])              // Register Value — attacker-controlled
    );
    pthread_mutex_unlock(&bufferLock);

    if (mb_error != ERR_NONE)
    {
        ModbusError(buffer, mb_error);
    }
    else
    {
        buffer[4] = 0;
        buffer[5] = 6;
        MessageLength = 12;                       // [6] Echo request as confirmation
    }
}
```

Note at [6]: the normal response has `MessageLength = 12`, meaning the response is the **first 12 bytes of the original request buffer echoed verbatim** — confirming the write succeeded. This is identical behavior to FC=05.

The `writeToRegisterWithoutLocking()` function (line 575) maps the register address to one of four PLC memory regions and writes the value directly ([7]–[10]):

```c
// modbus.cpp — writeToRegisterWithoutLocking() (line 575)
int writeToRegisterWithoutLocking(int position, uint16_t value)
{
    // Region 1: Analog Outputs (%QW) — addresses 0–1023
    if (position < MIN_16B_RANGE)                    // MIN_16B_RANGE = 1024
    {
        if (int_output[position] != NULL)
            *int_output[position] = value;           // [7] Direct write to PHYSICAL OUTPUT
    }
    // Region 2: 16-bit Memory (%MW) — addresses 1024–2047
    else if (position >= MIN_16B_RANGE && position <= MAX_16B_RANGE)
    {
        if (int_memory[position - MIN_16B_RANGE] != NULL)
            *int_memory[position - MIN_16B_RANGE] = value;  // [8] Write to internal state
    }
    // Region 3: 32-bit Memory (%MD) — addresses 2048–4095
    else if (position >= MIN_32B_RANGE && position <= MAX_32B_RANGE)
    {
        // Overwrites one 16-bit word of a 32-bit register
        int bit_offset = (1 - ((position - MIN_32B_RANGE) % 2)) * 16;
        *dint_memory[(position - MIN_32B_RANGE) / 2] &= ~(((uint32_t) 0xffff) << bit_offset);
        *dint_memory[(position - MIN_32B_RANGE) / 2] |= ((uint32_t) value) << bit_offset;  // [9]
    }
    // Region 4: 64-bit Memory (%ML) — addresses 4096–8191
    else if (position >= MIN_64B_RANGE && position <= MAX_64B_RANGE)
    {
        // Overwrites one 16-bit word of a 64-bit register
        int bit_offset = (3 - ((position - MIN_64B_RANGE) % 4)) * 16;
        *lint_memory[(position - MIN_64B_RANGE) / 4] &= ~(((uint64_t) 0xffff) << bit_offset);
        *lint_memory[(position - MIN_64B_RANGE) / 4] |= ((uint64_t) value) << bit_offset;  // [10]
    }
    else
    {
        return ERR_ILLEGAL_DATA_ADDRESS;
    }
    return ERR_NONE;
}
```

**Key observations**:

1. **Region 1 (addresses 0–1023) is the most critical**: `int_output[]` maps to IEC 61131-3 analog output variables (`%QW0` through `%QW1023`). These drive physical actuators — valve positions, motor speeds, temperature setpoints, pump commands. Writing here **immediately changes physical output state** on the next PLC scan cycle (~100ms).

2. **Regions 2–4 affect internal PLC logic**: Overwriting `int_memory[]`, `dint_memory[]`, or `lint_memory[]` can corrupt setpoints, counters, accumulated timer values, and calculation intermediates, causing the PLC program to produce incorrect outputs.

3. **No access control at any layer**: There is no check on `position`, no check on `value`, no authentication of the client, and no per-register write protection.

### 3.3 FC=06 vs FC=16: Why FC=06 Warrants Separate Attention

| Characteristic | FC=06 (Write Single Register) | FC=16 (Write Multiple Registers) |
|---------------|------------------------------|----------------------------------|
| **Request size** | **12 bytes** (minimum possible) | 15+ bytes |
| **Registers written** | Exactly 1 | 1–123 |
| **IDS evasion** | **Higher** — resembles normal SCADA polling | Lower — bulk write pattern is anomalous |
| **Code path** | `WriteRegister()` → `writeToRegisterWithoutLocking()` | `WriteMultipleRegisters()` → `writeToRegisterWithoutLocking()` |
| **Shared sink** | `writeToRegisterWithoutLocking()` | `writeToRegisterWithoutLocking()` |
| **Attack precision** | Surgical — modifies exactly 1 register | Can modify many, but not necessarily surgical |

FC=06 and FC=16 share the same vulnerable sink function (`writeToRegisterWithoutLocking()`), but FC=06 has a **distinct code path** through `WriteRegister()` with its own entry point, size validation, and response handling. Importantly, FC=06's 12-byte packet is the smallest possible Modbus write and closely mimics legitimate single-register SCADA operations (e.g., operator setpoint changes), making it significantly harder for signature-based IDS to detect.

---

## 4. Attack Scenario

### 4.1 Threat Model

An attacker with network access to an OpenPLC instance on TCP/502 can overwrite any holding register in a single 12-byte Modbus TCP request.

**Scenario**: Heat exchanger system. Register `%QW100` (address 0x0064) stores the temperature setpoint in tenths of degrees Celsius. Normal operating range: 400–800 (40.0–80.0°C). Design maximum: 1200 (120.0°C).

### 4.2 Attack Message

The following 12-byte Modbus TCP request overwrites register `0x0064` with value `0x07D0` (decimal 2000 = 200.0°C):

```
00 01 00 00 00 06 01 06 00 64 07 D0
|___| |___| |___| |  |  |___| |___|
  |     |     |   |  FC  Addr  Value = 2000 (200.0°C)
  |     |     |   Unit ID
  |     |     Length (6 bytes follow)
  |     Protocol ID (Modbus)
  Transaction ID
```

| Byte(s) | Field | Value | Meaning |
|---------|-------|-------|---------|
| 0–1 | Transaction ID | `0x0001` | Arbitrary |
| 2–3 | Protocol ID | `0x0000` | Modbus |
| 4–5 | Length | `0x0006` | 6 bytes follow |
| 6 | Unit Identifier | `0x01` | Slave 1 |
| 7 | Function Code | `0x06` | Write Single Register |
| 8–9 | Register Address | `0x0064` | Target register (attacker-chosen) |
| 10–11 | Register Value | `0x07D0` | 2000 (malicious setpoint: 200.0°C) |

**Server Response** — OpenPLC echoes the request verbatim, confirming the write:

```
00 01 00 00 00 06 01 06 00 64 07 D0
```

### 4.3 Physical Impact Chain

```
[Attacker]                    [OpenPLC]                   [Physical Process]
    |                             |                              |
    |-- FC=06, addr=0x0064 ------>|                              |
    |   value=2000 (200.0°C)      |                              |
    |                             |-- *int_output[100] = 2000 -->|
    |                             |                              |-- PID loop reads new setpoint
    |<-- echo (write confirmed) --|                              |-- Heater drives to 200.0°C
    |                             |                              |-- Exceeds design limit (120°C)
    |                             |                              |-- Overheat / overpressure
```

1. Attacker sends a single 12-byte packet.
2. `WriteRegister()` calls `writeToRegisterWithoutLocking(100, 2000)`.
3. `int_output[100]` (mapped to `%QW100`) is set to `2000`.
4. On the next PLC scan cycle (~100ms), the PID control loop reads the new setpoint.
5. The heater drives at full power toward 200.0°C, exceeding the design maximum of 120.0°C.
6. Without independent safety instrumented systems (SIS), this leads to overheating, overpressure, and potential equipment failure.

---

## 5. Proof of Concept

### 5.1 Test Environment

| Component | Configuration |
|-----------|---------------|
| **Target** | OpenPLC v3, Docker container (debian:trixie), `openplc_modbus` |
| **Modbus Port** | TCP/502 (default) |
| **PLC Program** | IEC 61131-3 ST with holding registers at `%QW0`–`%QW3` and `%IW0`–`%IW1` |
| **Attacker** | Python 3.11 with raw TCP sockets, container `modbus_client` |
| **Network** | Docker bridge 172.20.0.0/24 |

### 5.2 Reproduction Steps

1. Deploy OpenPLC v3 via Docker with a Modbus-enabled ST program
2. Start the PLC runtime via the web interface (port 8080)
3. From any host with TCP access to port 502:
   a. Initialize registers: reg[99]=1111 (sentinel), reg[100]=600 (safe setpoint), reg[101]=3333 (sentinel)
   b. Send FC=06 with Register Address `0x0064` and Register Value `0x07D0` (2000)
   c. Read back registers 99–101 via FC=03: confirm reg[100] changed, sentinels unchanged
4. Repeat with multiple addresses to verify full address space is writable

### 5.3 POC Script

Full POC code: `poc_write_single_reg_register_addr.py` (same directory).

### 5.4 Test Results

**Phase 1 — Precision Attack** (overwrite register 0x0064):

```
Pre-attack state:
  reg[99]  (0x0063) = 1111   ← sentinel
  reg[100] (0x0064) =  600   ← safe setpoint (60.0°C)
  reg[101] (0x0065) = 3333   ← sentinel

TX: 00 03 00 00 00 06 01 06 00 64 07 D0   ← FC=06, addr=0x0064, value=2000
RX: 00 03 00 00 00 06 01 06 00 64 07 D0   ← echo (write confirmed)

Post-attack state:
  reg[99]  (0x0063) = 1111   ← UNCHANGED (precision verified)
  reg[100] (0x0064) = 2000   ← OVERWRITTEN (600 → 2000, 60.0°C → 200.0°C)
  reg[101] (0x0065) = 3333   ← UNCHANGED (precision verified)
```

**Phase 2 — Address Space Sweep** (5 addresses tested):

| Address | Decimal | Written | Read-back | Result |
|---------|---------|---------|-----------|--------|
| `0x0000` | 0 | 500 | 500 | ✓ Write confirmed |
| `0x0032` | 50 | 600 | 600 | ✓ Write confirmed |
| `0x0064` | 100 | 700 | 700 | ✓ Write confirmed |
| `0x00C8` | 200 | 800 | 800 | ✓ Write confirmed |
| `0x01F4` | 500 | 999 | 999 | ✓ Write confirmed |

**Result: 5/5 addresses across the holding register space are writable without authentication via FC=06.**

---

## 6. Impact

The vulnerability allows an unauthenticated remote attacker to overwrite any holding register (0–8191) across four distinct PLC memory regions via a single 12-byte network request to TCP/502. No privileges, user interaction, or race conditions are required. Registers in the `%QW` (analog output) range immediately drive physical actuators on the next scan cycle, crossing the software boundary into the physical process. The 12-byte FC=06 request is the smallest possible Modbus write, making it harder to distinguish from legitimate SCADA traffic.

### ICS-Specific Safety Impact

In ICS/SCADA deployments, the four memory regions accessible via FC=06 control different aspects of physical processes:

| Memory Region | Addresses | Impact of Unauthorized Write |
|--------------|-----------|------|
| **`int_output[]` (%QW)** | 0–1023 | **Immediate physical change**: valve positions, motor speeds, heater setpoints |
| **`int_memory[]` (%MW)** | 1024–2047 | **Logic corruption**: PID parameters, alarm thresholds, interlock flags |
| **`dint_memory[]` (%MD)** | 2048–4095 | **State corruption**: accumulated counters, batch totals, timer presets |
| **`lint_memory[]` (%ML)** | 4096–8191 | **Precision corruption**: high-resolution timestamps, energy accumulators |

An attacker can combine writes to multiple regions in rapid succession (each requiring only 12 bytes) to:
- Override a temperature setpoint (`%QW`) **and** disable the alarm threshold (`%MW`) that would detect the change
- Corrupt a batch counter (`%MD`) while modifying the dosing rate (`%QW`)
- Achieve persistent manipulation by writing to both output and internal memory regions

---

## 7. CWE Classification

| CWE | Name | Application |
|-----|------|-------------|
| **CWE-306** | Missing Authentication for Critical Function | The FC=06 register write path performs no authentication. This is the primary CWE. |
| CWE-862 | Missing Authorization | Even if authentication were added, there is no register-level permission model. |

**Primary CWE: CWE-306** — consistent with:
- CVE-2025-54849 (Socomec DIRIS M-70, **CWE-306** — identical CWE, same function code FC=06)
- CVE-2025-54848 (Socomec DIRIS M-70, CWE-306 — same vulnerability class)
- CVE-2019-6533 (Kunbus PR100088, CWE-306 — missing auth for Modbus access, CVSS 10.0)

---

## 8. MITRE ATT&CK for ICS Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| **T0855** | Unauthorized Command Message | Sending FC=06 to write registers without authorization |
| **T0836** | Modify Parameter | Overwriting setpoint/threshold registers in `int_output[]` and `int_memory[]` |
| **T0831** | Manipulation of Control | Altering PLC output values to affect physical process |
| **T0856** | Spoof Reporting Message | Potential follow-up: overwrite input registers to hide the attack from HMI |

---

## 9. Comparison with Accepted CVEs

### 9.1 CVE Precedent Table

| CVE ID | Product | Year | CVSS | FC | CWE | Status |
|--------|---------|------|------|----|-----|--------|
| **CVE-2025-54849** | **Socomec DIRIS M-70** | **2025** | **7.5** | **FC=06** | **CWE-306** | **Assigned — closest precedent (same FC, same CWE)** |
| CVE-2025-54848 | Socomec DIRIS M-70 | 2025 | 7.5 | FC=06 | CWE-306 | Assigned (3-step DoS sequence) |
| CVE-2025-48466 | Advantech WISE-4060LAN | 2025 | 8.1 | FC=05 | CWE-863 | Assigned (coil write, same class) |
| CVE-2024-11737 | Schneider Modicon | 2024 | 9.8 | Multiple | CWE-20 | Assigned (CISA ICSA-24-352-04) |
| CVE-2019-6533 | Kunbus PR100088 | 2019 | 10.0 | N/A | CWE-306 | Assigned (CISA ICSA-19-036-05) |
| CVE-2025-53476 | **OpenPLC v3** | 2025 | 5.3 | N/A | CWE-775 | Assigned (Talos TALOS-2025-2223) |
| CVE-2025-54811 | **OpenPLC v3** | 2025 | 7.1 | N/A | CWE-758 | Assigned (CISA ICSA-25-273-05) |
| CVE-2025-13970 | **OpenPLC v3** | 2025 | 8.0 | N/A | CWE-352 | Assigned (CISA ICSA-25-345-10) |

### 9.2 Detailed Comparison with CVE-2025-54849 (Socomec)

CVE-2025-54849 is the closest existing precedent — it targets the **same function code (FC=06)** with the **same CWE (CWE-306)** on a different product:

| Aspect | CVE-2025-54849 (Socomec) | This Finding (OpenPLC) |
|--------|--------------------------|------------------------|
| **Product** | Socomec DIRIS Digiware M-70 | OpenPLC Runtime v3 |
| **Function Code** | FC=06 Write Single Register | FC=06 Write Single Register |
| **Root Cause** | Missing authentication for Modbus write | Missing authentication for Modbus write |
| **CWE** | CWE-306 | CWE-306 |
| **CVSSv3.1** | 7.5 (AV:N, C:N/I:N/**A:H**) | **8.6** (AV:N, C:N/**I:H**/A:N, **S:C**) |
| **Primary Impact** | **Availability** (DoS — device becomes unreachable) | **Integrity** (arbitrary register overwrite, physical output manipulation) |
| **Attack Scope** | Single specific register (4352) changes Modbus address | **All 8,192 registers** across 4 memory regions |
| **Physical Impact** | Monitoring device offline | **Actuator setpoints modified → physical damage** |
| **Fix** | Cyber Security profile disables Modbus writes | **None — no protection mechanism exists** |

**Key differences from CVE-2025-54849**:
1. Different product and vendor
2. Broader scope — 8,192 writable registers vs. one specific register
3. Different impact class — Integrity (physical output manipulation) vs. Availability (DoS)
4. No available mitigation — Socomec provides "Cyber Security" profile; OpenPLC has none

### 9.3 OpenPLC CNA Relationship

OpenPLC v3 has an established vulnerability handling ecosystem with 8+ assigned CVEs:

| CVE ID | Year | Reporter | CWE | Component |
|--------|------|----------|-----|-----------|
| CVE-2024-34026 | 2024 | Cisco Talos | Buffer Overflow | EtherNet/IP parser (RCE, CVSS 9.8) |
| CVE-2024-36980/36981 | 2024 | Cisco Talos | OOB Read | EtherNet/IP PCCC parser |
| CVE-2024-39589/39590 | 2024 | Cisco Talos | Null Deref | EtherNet/IP parser |
| CVE-2025-53476 | 2025 | Cisco Talos | CWE-775 | Modbus TCP DoS |
| CVE-2025-54811 | 2025 | CISA | CWE-758 | enipThread crash |
| CVE-2025-13970 | 2025 | UCF researchers | CWE-352 | Web UI CSRF |

This vulnerability affects a **different component** (Modbus FC=06 register write path) and **different CWE** (CWE-306 vs CWE-775/CWE-758/CWE-352) than all existing OpenPLC CVEs. The only existing Modbus-related OpenPLC CVE (CVE-2025-53476) is a connection exhaustion DoS — a completely different root cause and code path.

---

## 10. Suggested Remediation

### 10.1 Short-term: Register Write Protection

Add a per-register access control check in `WriteRegister()` before calling `writeToRegisterWithoutLocking()`:

```c
// Proposed fix in modbus.cpp
extern bool register_write_enabled[MAX_HOLD_REGS];  // configurable via web UI

void WriteRegister(unsigned char *buffer, int bufferSize)
{
    // ... existing size validation ...
    Start = word(buffer[8], buffer[9]);

    // NEW: Check write permission
    if (Start < MAX_HOLD_REGS && !register_write_enabled[Start])
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_ADDRESS);
        return;
    }

    // ... existing write logic ...
}
```

The same protection should be applied to `WriteMultipleRegisters()` (line 727), which uses the same `writeToRegisterWithoutLocking()` sink.

### 10.2 Medium-term: Value Range Validation + IP ACL

```c
// Per-register value range check
typedef struct { uint16_t min_val; uint16_t max_val; } reg_range_t;
extern reg_range_t register_ranges[MAX_HOLD_REGS];

// In WriteRegister():
uint16_t val = word(buffer[10], buffer[11]);
if (val < register_ranges[Start].min_val || val > register_ranges[Start].max_val) {
    ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
    return;
}
```

Add configurable IP whitelisting for Modbus TCP clients in `server.cpp`, following the approach adopted by Socomec in their CVE-2025-54849 fix and Advantech in their CVE-2025-48466 fix.

### 10.3 Long-term: Modbus/TCP Security

Implement the Modbus/TCP Security specification (Modbus.org, V2.1 2018) for TLS-based mutual authentication and role-based access control, consistent with CISA recommendations in advisories ICSA-25-273-05 and ICSA-25-345-10 for OpenPLC.

---

## 11. References

1. OpenPLC v3 source: `webserver/core/modbus.cpp`, line 635 (`WriteRegister()`)
2. OpenPLC v3 source: `webserver/core/modbus.cpp`, line 575 (`writeToRegisterWithoutLocking()` — shared sink)
3. OpenPLC v3 source: `webserver/core/modbus.cpp`, line 1107 (`processModbusMessage()`)
4. OpenPLC v3 source: `webserver/core/ladder.h`, lines 70–83 (`int_output[]`, `int_memory[]`, `dint_memory[]`, `lint_memory[]`)
5. OpenPLC v3 source: `webserver/core/server.cpp`, line 181 (`processMessage()`)
6. Modbus Application Protocol Specification V1.1b3, Section 6.6 "Write Single Register"
7. Modbus/TCP Security Protocol Specification, V2.1 (2018), Modbus.org
8. CVE-2025-54849 / TALOS-2025-2248 — Socomec DIRIS M-70 FC=06 unauthenticated register write (CWE-306, CVSS 7.5)
9. CVE-2025-54848 — Socomec DIRIS M-70 Modbus 3-step DoS (CWE-306, CVSS 7.5)
10. CVE-2025-48466 — Advantech WISE-4060LAN FC=05 unauthenticated coil write (CWE-863, CVSS 8.1)
11. CVE-2019-6533 / CISA ICSA-19-036-05 — Kunbus PR100088 missing auth for Modbus (CWE-306, CVSS 10.0)
12. TALOS-2025-2223 / CVE-2025-53476 — OpenPLC ModbusTCP DoS (Cisco Talos)
13. CISA ICSA-25-273-05 / CVE-2025-54811 — OpenPLC enipThread crash
14. CISA ICSA-25-345-10 / CVE-2025-13970 — OpenPLC CSRF
15. Al-Sabbagh et al., "Investigating the Security of OpenPLC," IEEE Access, 2024
16. NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security"
