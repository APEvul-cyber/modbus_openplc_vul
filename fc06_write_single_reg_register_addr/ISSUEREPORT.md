# FC06 write single holding register

Port 502 accepts this write with no authentication.

## Reproduce

`poc.py`

**Expected:** do not expose 502; or add an allowlist.

https://github.com/APEvul-cyber/modbus_openplc_vul/tree/main/fc06_write_single_reg_register_addr
