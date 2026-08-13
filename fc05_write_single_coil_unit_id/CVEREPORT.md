# OpenPLC v3: FC05 write single coil by Unit ID

**Affected:** OpenPLC v3 `webserver/core/modbus.cpp`, TCP port 502.  
**CWE:** CWE-306

Unauthenticated FC05 with attacker Unit ID. OpenPLC accepts and echoes the Unit ID; the coil write still lands.

Modbus TCP has no authentication. OpenPLC exposes the full 0–8191 map with no second control plane. Attackers on the network use the specified function codes. That is the CVE for any OpenPLC instance reachable on 502.

## Reproduce

`poc.py` in this directory.

**Actual:** write succeeds; no auth, no ACL.  
**Expected:** bind 502 to localhost / allowlist, or refuse writes without a session.

## References

- https://github.com/APEvul-cyber/modbus_openplc_vul/tree/main/fc05_write_single_coil_unit_id
