# Test matrix

| Case | jco-browser | jco-node | wasmtime-rustcrypto |
| --- | --- | --- | --- |
| probe (16 cases) | 7 N/A, 9 pass | pass | pass |
| rsa-oaep-decrypt/decline/minting | pass | N/A | N/A |
| rsa-oaep-sha256-2048 (80 cases) | N/A | pass | pass |
| rsa-oaep-sha256-2688 (16 cases) | N/A | pass | pass |
| rsa-oaep-sha256-3072 (80 cases) | N/A | pass | pass |
| rsa-oaep-sha256-4032 (12 cases) | N/A | pass | pass |
| rsa-oaep-sha256-4096 (80 cases) | N/A | pass | pass |
| rsa-oaep-sha256-8192 (6 cases) | N/A | pass | pass |
| rsa-oaep-sha384-2048 (74 cases) | N/A | pass | pass |
| rsa-oaep-sha384-3072 (6 cases) | N/A | pass | pass |
| rsa-oaep-sha384-3104 (6 cases) | N/A | pass | pass |
| rsa-oaep-sha384-4096 (6 cases) | N/A | pass | pass |
| rsa-oaep-sha384-8192 (6 cases) | N/A | pass | pass |
| rsa-oaep-sha512-2048 (72 cases) | N/A | pass | pass |
| rsa-oaep-sha512-3072 (72 cases) | N/A | pass | pass |
| rsa-oaep-sha512-4096 (78 cases) | N/A | pass | pass |
| rsa-oaep-sha512-8192 (6 cases) | N/A | pass | pass |
| rsa-sign/decline/minting | pass | N/A | N/A |
| rsassa-pkcs1-v15-sha256-2048 (20 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha256-3072 (18 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha256-4096 (16 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-2048 (16 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-3072 (16 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha384-4096 (16 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-2048 (18 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-3072 (18 cases) | N/A | pass | pass |
| rsassa-pkcs1-v15-sha512-4096 (16 cases) | N/A | pass | pass |

## Failures

None.

## Summary

- `jco-browser`: 761 N/A, 11 pass (772 total)
- `jco-node`: 2 N/A, 770 pass (772 total)
- `wasmtime-rustcrypto`: 2 N/A, 770 pass (772 total)
