# OpenPLC v3: unauthenticated Modbus writes to coils/registers

**Affected:** OpenPLC v3 `webserver/core/modbus.cpp`, port 502.  
**CWE:** CWE-306

No auth on Modbus TCP. FC05/06/16 write any coil/holding register in the 0–8191 map. Unit ID is accepted and echoed (normal for TCP).

This is the Modbus threat model. Report exists because OpenPLC is often exposed on a network with no second control plane.

## Reproduce

`fc05_*` / `fc06_*` / `fc16_*/poc.py`.

**Fix:** bind to localhost or add a allowlist; do not expose 502 to untrusted nets.
