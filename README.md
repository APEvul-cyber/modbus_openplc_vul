# Modbus TCP Vulnerabilities in OpenPLC v3

This repository documents five independently verified vulnerabilities in the Modbus TCP server implementation of [OpenPLC v3](https://github.com/thiagoralves/OpenPLC_v3).

All vulnerabilities stem from missing input validation and access control in `webserver/core/modbus.cpp`. An unauthenticated attacker with network access to the Modbus TCP port (default 502) can exploit these issues to manipulate PLC memory and physical outputs.

## Affected Software

| Field | Value |
|-------|-------|
| **Product** | OpenPLC v3 (OpenPLC Runtime) |
| **Component** | `webserver/core/modbus.cpp` |
| **Protocol** | Modbus TCP (port 502) |

## Vulnerabilities

| # | Directory | Function Code | Vulnerability |
|---|-----------|--------------|---------------|
| 1 | [`fc16_write_multiple_regs_starting_addr`](./fc16_write_multiple_regs_starting_addr/) | FC=16 (Write Multiple Registers) | No starting address validation — any holding register (0–8191) can be overwritten |
| 2 | [`fc16_write_multiple_regs_unit_id`](./fc16_write_multiple_regs_unit_id/) | FC=16 (Write Multiple Registers) | No Unit Identifier validation — any Unit ID is accepted and echoed back |
| 3 | [`fc05_write_single_coil_output_addr`](./fc05_write_single_coil_output_addr/) | FC=05 (Write Single Coil) | No output address validation — any coil (0–8191) can be toggled |
| 4 | [`fc05_write_single_coil_unit_id`](./fc05_write_single_coil_unit_id/) | FC=05 (Write Single Coil) | No Unit Identifier validation — compound with unrestricted coil write |
| 5 | [`fc06_write_single_reg_register_addr`](./fc06_write_single_reg_register_addr/) | FC=06 (Write Single Register) | No register address validation — any holding register can be overwritten with a single 12-byte packet |

## Repository Structure

Each subdirectory contains:

- **`report.md`** — Full vulnerability report (description, root cause analysis, affected code, attack scenario, PoC results, remediation)
- **`poc.py`** — Python proof-of-concept script (requires `pymodbus>=3.6`)

## Reproduction Environment

- OpenPLC v3 running in Docker (Debian Trixie)
- Modbus TCP enabled on port 502
- Test PLC program with coils (`%QX`) and holding registers (`%QW`) mapped
- Python 3.11 + `pymodbus 3.6.9` as the Modbus client

## Disclaimer

These vulnerabilities are disclosed for security research purposes. The proof-of-concept scripts are provided to facilitate verification and should only be used in authorized test environments.
