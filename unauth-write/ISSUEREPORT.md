# Unauthenticated Modbus writes on port 502

FC05/06/16 write coils and holding registers with no auth. Attackers on the network use that.

Please bind 502 to localhost or add an allowlist. Per-function PoCs are in the `fc05_*` / `fc06_*` / `fc16_*` dirs.
