# lc-webhook

`detect.json` is a synthetic LimaCharlie `detect` webhook body, byte for byte in the
shape a real delivery has: one detection per request, compact JSON, keys sorted, no
trailing newline. Every value is made up (zero org id, documentation IP ranges).

The signature recipe it pins is tested in `api/tests/test_lc_signature.py`.
