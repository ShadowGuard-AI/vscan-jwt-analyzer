# vscan-jwt-analyzer
Analyzes JWT (JSON Web Tokens) for common vulnerabilities such as weak algorithms, missing signature verification, and exposed secrets. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-jwt-analyzer`

## Usage
`./vscan-jwt-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ

## Parameters added
- `--secret`: Operator supplied candidate secret for the weak secret test. May be given more than once.
- `--secret-file`: File with one operator supplied candidate secret per line for the weak secret test.
- `--show-payload-values`: Show decoded payload claim values in full. By default only claim names and value types are shown and values are masked.

## Behaviour notes
HMAC signatures (HS256, HS384, HS512) are verified with the standard library against operator supplied candidates only; no secret is built into the tool, and results report candidate indexes, never candidate values. A token with alg `none` is reported as unverifiable, never as a successful verification. The `exp` and `nbf` claims are compared with the current time. A token that cannot be decoded exits non-zero.
