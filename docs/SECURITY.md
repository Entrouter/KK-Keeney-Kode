# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**KK-Crypto is an experimental, un-audited cryptographic primitive.
It is NOT recommended for production use.**

If you discover a security vulnerability:

1. **Do NOT open a public issue.**
2. Email **security@entrouter.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
3. You will receive an acknowledgement within 48 hours.
4. A fix will be developed privately and disclosed responsibly.

## Scope

This policy covers vulnerabilities in the KK-Crypto Rust crate:
- The KK permutation (`kk_mix.rs`)
- Key derivation (`kdf.rs`)
- Encoding/decoding (`codec.rs`)
- Session management (`session.rs`)
- EKA key agreement (`eka.rs`)
- Temporal proofs (`temporal.rs`)

## Third-Party Audit Status

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
|  -    |  -       |  -     | No audit has been conducted yet. |

KK-Crypto has **not** been independently audited. When an audit is arranged,
this table will be updated with the auditor, scope, and a link to the report.

Until then, this crate should be treated as **experimental and un-audited**.

## Acknowledgements

We appreciate responsible disclosure and will credit researchers
(with permission) in the CHANGELOG.
