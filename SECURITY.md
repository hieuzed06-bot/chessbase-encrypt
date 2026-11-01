# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** feature on this repository (Security → Advisories), if available. Do not publish exploit details in a public issue before the maintainer has had a chance to investigate.

Include the affected file or feature, reproduction steps, impact, and any suggested mitigation. Do not include real passwords, private source code, or other secrets in the report.

## Cryptographic design

- New encryptions use Web Crypto AES-256-GCM with a fresh random 16-byte salt and 12-byte IV.
- The AES key is derived with PBKDF2-HMAC-SHA-256 using 600,000 iterations.
- The decryptor also supports older files made with 100,000 PBKDF2 iterations.
- AES-GCM authentication detects modified ciphertext. The chess-move representation is only an encoding layer; it is not additional cryptographic protection.

## Safe use

- Use a unique, long password (ideally 16+ characters); there is no password recovery.
- Send the password through a channel separate from the PGN or HTML file.
- Do not paste production credentials, API keys, or other high-value secrets into a page hosted on a public website. Prefer a trusted local copy and review the source before use.
- A downloaded self-decrypting HTML file contains executable JavaScript. Open it only if you trust the source.
- The repository's meta Content Security Policy is defense in depth. Hosting platforms may control HTTP response headers separately; this project does not configure those headers.


## Additional browser-side hardening

The main application JavaScript is served as a same-origin module and the main page CSP no longer permits inline scripts or event-handler attributes. Generated protected HTML uses a cryptographically random per-file nonce for its embedded decryptor. Source and PGN inputs are size-bounded, and the PGN parser rejects tokens outside the cipher's exact move alphabet. These controls reduce attack surface but do not make untrusted downloaded HTML safe to execute; only open protected pages from sources you trust.
