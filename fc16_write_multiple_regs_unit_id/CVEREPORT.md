# OpenPLC v3: FC16 write multiple registers by Unit ID

**Affected:** OpenPLC v3 `webserver/core/modbus.cpp`, TCP port 502.  
**CWE:** CWE-306

Unauthenticated FC16 with attacker Unit ID. Same write, different addressing field.

Modbus TCP has no authentication. OpenPLC exposes the full 0–8191 map with no second control plane. Attackers on the network use the specified function codes. That is the CVE for any OpenPLC instance reachable on 502.

## Reproduce

`poc.py` in this directory.

**Actual:** write succeeds; no auth, no ACL.  
**Expected:** bind 502 to localhost / allowlist, or refuse writes without a session.

## References

- https://github.com/APEvul-cyber/modbus_openplc_vul/tree/main/fc16_write_multiple_regs_unit_id
