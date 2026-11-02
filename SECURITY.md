# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** feature on this repository (Security → Advisories), if available. Do not publish exploit details in a public issue before the maintainer has had a chance to investigate.

Include the affected file or feature, reproduction steps, impact, and any suggested mitigation. Do not include real passwords, private source code, or other secrets in the report.

## Cryptographic design

- New CCX v3 encryptions use Web Crypto AES-256-GCM with a fresh random 16-byte salt and 12-byte nonce, plus a 128-bit authentication tag.
- Passwords are processed with PBKDF2-HMAC-SHA-256 at 1,000,000 iterations. HKDF-SHA-256 derives the dedicated AES key with a domain-separated context.
- A fixed canonical Additional Authenticated Data (AAD) value binds the format version, KDF, work factor, cipher and codec identifier. Altered or mismatched metadata causes authentication failure.
- Plaintext is length-prefixed and padded with random bytes to the next power-of-two bucket (minimum 256 bytes), reducing exact-length leakage but not hiding the bucket or total PGN size.
- The versioned CCX v3 envelope begins with the `CCX3` marker, then salt, nonce and ciphertext+tag. The chess notation remains a reversible encoding layer, not cryptographic protection.
- Decryption remains compatible with v2 files (PBKDF2-SHA-256, 600,000 iterations) and legacy files (100,000 iterations).
- PBKDF2 is not memory-hard like Argon2id. This implementation intentionally uses browser-native Web Crypto to remain self-contained and offline-capable; do not claim Argon2id protection. A future Argon2id migration should bundle and audit a maintained implementation.

## Safe use

- New encryptions enforce a minimum of 16 Unicode characters and a maximum of 1,024 UTF-8 bytes; the UI also requires password confirmation. Decryption remains backward-compatible with existing shorter passwords.
- Use a unique, long passphrase; there is no password recovery.
- Send the password through a channel separate from the PGN or HTML file.
- Do not paste production credentials, API keys, or other high-value secrets into a page hosted on a public website. Prefer a trusted local copy and review the source before use.
- A downloaded self-decrypting HTML file contains executable JavaScript. Open it only if you trust the source.
- The repository's meta Content Security Policy is defense in depth. Hosting platforms may control HTTP response headers separately; this project does not configure those headers.


## Additional browser-side hardening

The main application JavaScript is served as a same-origin module and the main page CSP no longer permits inline scripts or event-handler attributes. Generated protected HTML uses a cryptographically random per-file nonce for its embedded decryptor. Source and PGN inputs are size-bounded, and the PGN parser rejects tokens outside the cipher's exact move alphabet. These controls reduce attack surface but do not make untrusted downloaded HTML safe to execute; only open protected pages from sources you trust.
