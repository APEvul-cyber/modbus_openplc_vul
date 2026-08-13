# modbus_openplc_vul

OpenPLC v3 Modbus TCP has no authentication. Each write function is a reachable attacker primitive.

| Dir | Issue |
|---|---|
| `fc05_write_single_coil_output_addr` | FC05 write single coil by address |
| `fc05_write_single_coil_unit_id` | FC05 write single coil by Unit ID |
| `fc06_write_single_reg_register_addr` | FC06 write single holding register |
| `fc16_write_multiple_regs_starting_addr` | FC16 write multiple registers by start address |
| `fc16_write_multiple_regs_unit_id` | FC16 write multiple registers by Unit ID |
