# FC16 write multiple registers by Unit ID

Port 502 accepts this write with no authentication.

## Reproduce

`poc.py`

**Expected:** do not expose 502; or add an allowlist.

https://github.com/APEvul-cyber/modbus_openplc_vul/tree/main/fc16_write_multiple_regs_unit_id
