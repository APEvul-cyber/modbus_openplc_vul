# Vulnerability Report: OpenPLC v3 ModbusTCP Server Missing Unit Identifier Validation

## Metadata

| Field | Value |
|-------|-------|
| **Vendor** | OpenPLC Project (Thiago Alves) |
| **Product** | OpenPLC Runtime v3 |
| **Product URL** | https://github.com/thiagoralves/OpenPLC_v3 |
| **Affected Version** | OpenPLC_v3 master branch (all versions using `webserver/core/modbus.cpp`) |
| **Tested Version** | OpenPLC_v3 (downloaded 2026-01, Docker build on debian:trixie) |
| **CWE** | CWE-20: Improper Input Validation |

---

## 1. Summary

An input validation vulnerability exists in the Modbus TCP server functionality of OpenPLC_v3. The `processModbusMessage()` function in `webserver/core/modbus.cpp` **never reads, validates, or filters the Unit Identifier field** (`buffer[6]`) in the MBAP header of incoming Modbus TCP requests. Regardless of the Unit Identifier value (any value from `0x00` to `0xFF`), the server processes the enclosed PDU and echoes the attacker-supplied Unit Identifier back in the response.

This is a distinct implementation defect:

1. **No server-side Unit ID configuration exists**: While OpenPLC provides Slave ID configuration for its Modbus *Master* functionality (outbound polling), the Modbus *Server* (inbound listener on TCP/502) has **no configurable device address**. There is no setting — in the web UI, database, configuration file, or source code — to define "this device's Unit ID."

2. **The response echoes the attacker's Unit ID**: Because all response functions reuse the request buffer without modifying `buffer[6]`, the server appears to "claim" whatever Unit ID the attacker specifies. In gateway deployments, this causes the gateway to route the response back to the attacker, confirming successful manipulation of a device the request was never intended for.

3. **All function codes are affected**: The vulnerability is in `processModbusMessage()` which dispatches all 13 supported function codes (FC=1–6, 15–16, 0x41–0x45). Every read and write operation is exploitable via any Unit ID.

---

## 2. Confirmed Vulnerable Version

OpenPLC Runtime v3, downloaded from `https://github.com/thiagoralves/OpenPLC_v3` (master branch).

The vulnerable code in `processModbusMessage()` (line 1107 of `modbus.cpp`) has remained structurally unchanged across all known versions of OpenPLC v3.

---

## 3. Technical Details

OpenPLC is an open-source programmable logic controller designed for automation and ICS security research. It supports Modbus TCP on TCP/502 and EtherNet/IP. The runtime can be deployed on Linux, Windows, and embedded platforms. OpenPLC is cited in numerous academic ICS security papers and is used in educational and small-scale industrial deployments.

### 3.1 Vulnerability Root Cause

The MBAP (Modbus Application Protocol) header in Modbus TCP consists of 7 bytes:

```
Byte 0-1: Transaction Identifier
Byte 2-3: Protocol Identifier (0x0000 = Modbus)
Byte 4-5: Length (number of following bytes)
Byte 6:   Unit Identifier    ← THIS FIELD IS NEVER VALIDATED
Byte 7+:  PDU (Function Code + Data)
```

Per the **MODBUS Messaging on TCP/IP Implementation Guide V1.0b, Section 4.2**, the Unit Identifier is used for "intra-system routing purpose" to address specific devices behind a Modbus TCP-to-RTU gateway. A conformant server should only process requests addressed to its own Unit ID (or the broadcast address `0x00` / TCP wildcard `0xFF`).

OpenPLC's `processModbusMessage()` begins parsing at `buffer[7]` (the Function Code) and **completely skips `buffer[6]`** (the Unit Identifier). The field is not read into any variable, not compared against any configured value, and not logged.

### 3.2 Code Flow Analysis

The complete call path from connection acceptance to register write is:

**`server.cpp:startServer()` → `server.cpp:handleConnections()` → `server.cpp:processMessage()` → `modbus.cpp:processModbusMessage()` → `modbus.cpp:WriteMultipleRegisters()`**

When a Modbus TCP client connects, `handleConnections()` reads the message and calls `processMessage()`, which dispatches to `processModbusMessage()` ([1]):

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

Note at [2]: the response is sent using the **same `buffer`** that contains the original request. Since `buffer[6]` (Unit Identifier) is never modified by any processing function, the attacker's Unit ID is echoed verbatim in the response.

Inside `processModbusMessage()`, the code begins parsing at `buffer[7]` (Function Code) and `buffer[8..9]` (first PDU field). **`buffer[6]` is never referenced** ([3]):

```c
// modbus.cpp — processModbusMessage() (line 1107)
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    uint16_t field1 = (uint16_t)buffer[8] << 8 | (uint16_t)buffer[9];   // [3a] starts at buffer[8]
    uint16_t field2 = (uint16_t)buffer[10] << 8 | (uint16_t)buffer[11]; // [3b]
    uint8_t flag = buffer[10];                                           // [3c]
    uint16_t len = (uint16_t)buffer[11] << 8 | (uint16_t)buffer[12];    // [3d]
    void *value = &buffer[13];                                           // [3e]
    void *endianness_check = &buffer[8];                                 // [3f]

    // *** buffer[6] (Unit Identifier) is NEVER read, checked, or stored ***

    if (bufferSize < 8)
    {
        ModbusError(buffer, ERR_ILLEGAL_FUNCTION);
    }
    else if(buffer[7] == MB_FC_READ_COILS)            // FC=1
    {
        ReadCoils(buffer, bufferSize);
    }
    else if(buffer[7] == MB_FC_READ_INPUTS)           // FC=2
    {
        ReadDiscreteInputs(buffer, bufferSize);
    }
    else if(buffer[7] == MB_FC_READ_HOLDING_REGISTERS) // FC=3
    {
        ReadHoldingRegisters(buffer, bufferSize);
    }
    // ... 10 more function code branches, ALL skip buffer[6] ...
    else if(buffer[7] == MB_FC_WRITE_MULTIPLE_REGISTERS) // FC=16
    {
        WriteMultipleRegisters(buffer, bufferSize);    // [4] No Unit ID check before dispatch
    }
    // ...
}
```

The response functions (including `ModbusError()`) also never modify `buffer[6]` ([5]):

```c
// modbus.cpp — ModbusError() (line 164)
void ModbusError(unsigned char *buffer, int mb_error)
{
    buffer[4] = 0;
    buffer[5] = 3;
    buffer[7] = buffer[7] | 0x80;
    buffer[8] = mb_error;
    MessageLength = 9;
    // NOTE: buffer[6] (Unit ID) is untouched — attacker's value persists in response
}                                                      // [5]
```

### 3.3 Missing Server-Side Unit ID Configuration

OpenPLC provides Slave ID configuration for its **Modbus Master** role (when polling downstream devices):

```python
# webserver.py (line 307) — Modbus Master configuration
mbconfig += 'device' + str(device_counter) + '.slave_id = "' + str(row[3]) + '"\n'
```

```html
<!-- webserver.py (line 1315) — Web UI for Modbus Master slave configuration -->
<label for='dev_id'><b>Slave ID</b></label>
<input type='text' id='dev_id' name='device_id' placeholder='0'>
```

However, for the **Modbus Server** role (TCP/502 listener), there is:
- **No `unit_id` configuration** in `server.cpp` or `modbus.cpp`
- **No database field** for server-side Unit ID
- **No web UI setting** to define "this PLC's Modbus address"
- **No command-line parameter** or environment variable
- **No hardcoded default** that could be compared against incoming requests

This asymmetry (Master has Slave ID config; Server has no Unit ID config) is a concrete implementation gap.

---

## 4. Attack Scenario

### 4.1 Threat Model

An attacker on a flat OT network reaches an OpenPLC instance (directly or behind a Modbus TCP gateway) on TCP/502. The attacker has prior knowledge of the register map (from documentation, reconnaissance, or default mappings).

### 4.2 Attack Messages

**Attack Request** — Write holding register `0x0064` with value 260 (dangerous temperature setpoint), using Unit ID `0x07` (targeting a specific downstream PLC):

```
00 01 00 00 00 09 07 10 00 64 00 01 02 01 04
|___| |___| |___| |  |  |___| |___| |  |___|
  |     |     |   |  FC  Addr  Qty  BC  Value
  |     |     |   Unit ID = 0x07 ← attacker-chosen, NOT the PLC's address
  |     |     Length
  |     Protocol ID
  Transaction ID
```

**Server Response** — OpenPLC echoes `0x07` in the Unit ID field:

```
00 01 00 00 00 06 07 10 00 64 00 01
                  ^^
              Unit ID = 0x07 echoed — server "claims" to be device 7
```

| Byte(s) | Field | Request | Response | Note |
|---------|-------|---------|----------|------|
| 6 | Unit Identifier | `0x07` | `0x07` | **Echoed verbatim — no validation** |
| 7 | Function Code | `0x10` | `0x10` | FC=16 confirmed |
| 8–9 | Starting Address | `0x0064` | `0x0064` | Write target confirmed |
| 10–11 | Quantity | `0x0001` | `0x0001` | 1 register written |

### 4.3 Impact in Gateway Deployments

```
[Attacker] --unit_id=0x07--> [Modbus TCP Gateway] --routes to--> [PLC #7: Boiler Controller]
                                      |
                        [OpenPLC (Unit ID not checked)]
                        Responds with unit_id=0x07 ← spoofed identity
```

In this deployment:
1. The gateway receives a request for Unit ID `0x07` and forwards it to the serial bus
2. OpenPLC (which may be Unit ID `0x01`) processes the request anyway because it doesn't check
3. OpenPLC responds with Unit ID `0x07`, causing the gateway to believe PLC #7 responded
4. The actual PLC #7 never received the request, but the attacker's write was executed on OpenPLC

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
   a. Send an FC=16 request with `unit_id=0x01` and value `180` to register `0x0064` → observe success
   b. Send an FC=16 request with `unit_id=0x07` and value `260` to register `0x0064` → observe success (same register overwritten, different Unit ID accepted)
   c. Read back register `0x0064` via FC=03 → confirm value is now `260`
4. Repeat with Unit IDs `0x00`, `0xFF`, `0x42` — all are accepted

### 5.3 POC Script

Full POC code: `poc_write_multiple_regs_unit_id.py` (same directory).

The script executes 4 phases:
1. **Initialize**: Write safe value `180` to register `0x0064` using `unit_id=0x01`
2. **Core Attack**: Write malicious value `260` using `unit_id=0x07` — **succeeds**
3. **Unit ID Sweep**: Test 5 different Unit IDs (0x01, 0x07, 0x00, 0xFF, 0x42) — **all accepted**
4. **Restore**: Reset register to 0

### 5.4 Test Results

**Phase 2 — Core Attack** (unit_id=0x07, non-default):

```
TX: 00 03 00 00 00 09 07 10 00 64 00 01 02 01 04
                      ^^                         
                  unit_id=0x07 (not the PLC's address)

RX: 00 03 00 00 00 06 07 10 00 64 00 01
                      ^^
                  unit_id=0x07 ECHOED (server claims to be device 7)

Result: Register 0x0064 overwritten: 180 → 260 (confirmed via FC=03 read-back)
```

**Phase 3 — Full Unit ID Sweep**:

| Unit ID | Description | FC=16 Write | Response Unit ID | FC=03 Read-back | Accepted |
|---------|-------------|-------------|-----------------|-----------------|----------|
| `0x01` | Default | ✓ Success | `0x01` (echoed) | 101 | **Yes** |
| `0x07` | Non-default (attack target) | ✓ Success | `0x07` (echoed) | 107 | **Yes** |
| `0x00` | Broadcast address | ✓ Success | `0x00` (echoed) | 100 | **Yes** |
| `0xFF` | TCP wildcard | ✓ Success | `0xFF` (echoed) | 355 | **Yes** |
| `0x42` | Arbitrary value | ✓ Success | `0x42` (echoed) | 166 | **Yes** |

**Result: 5/5 Unit IDs accepted and echoed — zero validation performed across the entire 0x00–0xFF range.**

---

## 6. Impact

The vulnerability allows an unauthenticated remote attacker to send Modbus TCP requests with any Unit Identifier value (0x00–0xFF) to TCP/502. The server processes every request regardless of Unit ID and echoes the attacker-supplied value in the response. No privileges or user interaction are required.

### ICS-Specific Impact

| Deployment Model | Impact |
|-----------------|--------|
| **Direct TCP connection** | Attacker uses any Unit ID to read/write all registers — Unit ID cannot serve as a device isolation mechanism |
| **Behind Modbus TCP-to-RTU gateway** | Attacker spoofs Unit ID to target specific downstream PLCs; OpenPLC responds as the spoofed device, enabling blind routing attacks |
| **Multi-device bus** | No Unit ID-based access control is possible; all devices on the bus are reachable through OpenPLC |

---

## 7. CWE Classification

| CWE | Name | Application |
|-----|------|-------------|
| **CWE-20** | Improper Input Validation | The Unit Identifier field in the MBAP header is never validated against any configured or expected value. **This is the primary CWE.** |
| CWE-284 | Improper Access Control | The absence of Unit ID filtering means the server cannot restrict which device identity is accepted |

**Primary CWE: CWE-20** — The MBAP Unit Identifier is an input field that should be validated before processing the enclosed PDU. OpenPLC does not validate it at all. This is consistent with CVE-2024-8936 (Schneider Modicon, CWE-20) and CVE-2024-11737 (Schneider Modicon, CWE-20), both of which address improper input validation in Modbus processing.

---

## 8. MITRE ATT&CK for ICS Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| **T0855** | Unauthorized Command Message | Sending Modbus commands with spoofed Unit Identifier |
| **T0836** | Modify Parameter | Overwriting holding registers via the spoofed request |
| **T0830** | Man in the Middle | Unit ID spoofing enables routing-level deception in gateway deployments |
| **T0856** | Spoof Reporting Message | Response with echoed fake Unit ID spoofs the identity of the responding device |

---

## 9. Comparison with Accepted CVEs

| CVE ID | Product | Year | CVSS | CWE | Relevance |
|--------|---------|------|------|-----|-----------|
| **CVE-2024-11737** | **Schneider Modicon** | **2024** | **9.8** | **CWE-20** | **Closest precedent: improper input validation in Modbus processing** |
| CVE-2024-8936 | Schneider Modicon | 2024 | 6.5 | CWE-20 | Improper validation of Modbus function calls |
| CVE-2025-48466 | Advantech WISE-40x0 | 2025 | 8.1 | CWE-863 | Unauthenticated Modbus write (different field, same protocol) |
| CVE-2025-54848 | Socomec DIRIS M-70 | 2025 | 7.5 | CWE-306 | Unauthenticated Modbus register write |
| CVE-2025-53476 | **OpenPLC v3** | 2025 | 5.3 | CWE-775 | Prior OpenPLC CVE by Cisco Talos (different component) |
| PLC4X-156 | Apache PLC4X | 2020 | — | — | Client-side Unit ID bug (hardcoded to broadcast) |

**Differentiation from existing OpenPLC CVEs**: OpenPLC v3 has 16+ assigned CVEs, none of which address MBAP Unit Identifier handling. The closest (CVE-2025-53476) is a DoS in connection handling (CWE-775), a completely different root cause and code path.

---

## 10. Suggested Remediation

### 10.1 Short-term: Unit ID Validation in processModbusMessage()

Add a configurable Unit ID check at the entry point of Modbus message processing:

```c
// modbus.cpp — proposed fix
extern uint8_t configured_unit_id;  // set via web UI, default 0xFF

int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;

    // NEW: Validate Unit Identifier
    uint8_t received_uid = buffer[6];
    if (received_uid != configured_unit_id &&
        received_uid != 0x00 &&    // broadcast
        received_uid != 0xFF)      // TCP wildcard
    {
        // Option A: return Modbus exception (Gateway Target Device Failed to Respond)
        ModbusError(buffer, 0x0B);
        return MessageLength;
        // Option B: silently discard (do not respond)
        // return 0;
    }

    // ... existing function code dispatch ...
}
```

### 10.2 Medium-term: Web UI Configuration

Add a "Modbus Server Unit ID" setting in the OpenPLC web interface (`webserver.py`), stored in the SQLite database alongside existing Modbus Master slave configurations:

```python
# webserver.py — new setting in Settings page
# "Modbus Server Unit ID" (default: 255 / 0xFF)
```

### 10.3 Long-term: Modbus/TCP Security

Implement the Modbus/TCP Security specification (Modbus.org, V2.1 2018) for TLS-based authentication and role-based access control.

---

## 11. References

1. OpenPLC v3 source code: `webserver/core/modbus.cpp`, line 1107 (`processModbusMessage()`)
2. OpenPLC v3 source code: `webserver/core/modbus.cpp`, line 164 (`ModbusError()` — response echoes buffer[6])
3. OpenPLC v3 source code: `webserver/webserver.py`, line 307 (Modbus Master slave_id config — server side has none)
4. OpenPLC v3 source code: `webserver/core/server.cpp`, line 181 (`processMessage()` — response reuses request buffer)
5. MODBUS Messaging on TCP/IP Implementation Guide V1.0b, Section 4.2 (Unit Identifier definition)
6. Modbus Application Protocol Specification V1.1b3
7. Modbus/TCP Security Protocol Specification, V2.1 (2018), Modbus.org
8. TALOS-2025-2223 / CVE-2025-53476 — OpenPLC ModbusTCP DoS (prior OpenPLC CVE by Cisco Talos)
9. CISA ICS Advisory ICSA-25-273-05 — OpenPLC_V3
10. CVE-2024-11737 / CVE-2024-8936 — Schneider Modicon Modbus input validation (CWE-20 precedent)
11. Al-Sabbagh et al., "Investigating the Security of OpenPLC," IEEE Access, 2024
12. NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security"
