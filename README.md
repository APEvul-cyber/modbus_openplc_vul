# modbus_openplc_vul

OpenPLC v3 Modbus TCP (`modbus.cpp`) has no authentication (Modbus as specified) and no extra address ACL. Five PoCs show unauthenticated coil/register writes.

Not five CVEs — one access model. Reports collapsed to `unauth-write/`.
