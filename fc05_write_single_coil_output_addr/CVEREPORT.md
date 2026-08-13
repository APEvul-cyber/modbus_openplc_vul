# OpenPLC v3: FC05 write single coil by address

**Affected:** OpenPLC v3 `webserver/core/modbus.cpp`, TCP port 502.  
**CWE:** CWE-306

Unauthenticated FC05 writes coil 0x0064 (pump RUN) to OFF. Address is attacker-chosen.

Modbus TCP has no authentication. OpenPLC exposes the full 0–8191 map with no second control plane. Attackers on the network use the specified function codes. That is the CVE for any OpenPLC instance reachable on 502.

## Reproduce

`poc.py` in this directory.

**Actual:** write succeeds; no auth, no ACL.  
**Expected:** bind 502 to localhost / allowlist, or refuse writes without a session.

## References

- https://github.com/APEvul-cyber/modbus_openplc_vul/tree/main/fc05_write_single_coil_output_addr
