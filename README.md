# 🔐 Code Locker — Chess Cipher v3

> **Creative Chess Notation Encryption** — turn any source code into a PGN chess game record that still decrypts with AES-256-GCM.

---

## ✨ What It Does

`Code Locker` disguises encrypted source code as a **real-looking chess game record**. Behind the board: **AES-256-GCM** + **PBKDF2-SHA256 (1,000,000 iterations)** + **HKDF-SHA256 key derivation**. New v3 files use random length padding and authenticated version metadata. Existing v2 and legacy files remain decryptable. The output is either a PGN text or a self-contained HTML page — recipients just open it, enter the password, and the code is revealed.

| | |
|---|---|
| 🔒 **Protect tab** | paste code + password → get PGN / self-decrypting HTML |
| 🔓 **Unlock tab** | paste PGN (or protected HTML) + password → get code back |
| 📁 **File support** | PDF, Excel, Word, Lua/Luau, TXT, JS, SH, C#, PowerShell and terminal scripts |
| 🌐 **Any language** | Paste text or upload supported files; binary documents are encrypted as raw bytes |

---

## 🔐 How to Encrypt (Protect tab — CCX v3)

![Encryption pipeline](https://github.com/hieuzed06-bot/script/blob/main/image/encryption-flow.png)

1. **Open Code Locker** in a modern browser and stay on **🔒 Protect code**.
2. **Paste text/terminal commands**, or choose a supported file: `.pdf`, `.xls`, `.xlsx`, `.xlsm`, `.doc`, `.docx`, `.docm`, `.lua`, `.luau`, `.txt`, `.js`, `.sh`, `.bash`, `.zsh`, `.cs`, `.bat`, `.cmd`, `.ps1`, and common text formats.
3. Files are encrypted byte-for-byte, so PDF/Office documents are not converted to text. The encrypted payload limit is **1 MiB**.
4. Enter a password of at least 16 characters and confirm it. ⚠️ There is **no password recovery**.
5. Click **Encrypt**, then download a binary `.ccx` file, copy the PGN, or download a self-decrypting HTML page.

Every encryption uses a **fresh random salt + IV**, so encrypting the same code twice gives two completely different chess games.

---

## ♟️ How Bytes Become Moves

Every byte (0–255) maps to a chess move via 4 piece groups × 8 files × 8 ranks = **256 slots**. The two high bits pick the *piece board*, three middle bits pick the *file*, three low bits pick the *rank*:

![Four chess boards showing byte ranges](https://github.com/hieuzed06-bot/script/blob/main/image/chess-board-mapping.png)

### Byte anatomy — one worked example

![Byte 0xC3 breaks into piece, file, rank](https://github.com/hieuzed06-bot/script/blob/main/image/byte-anatomy.png)

### Key samples of the mapping

| Byte (hex) | Top 2 bits → Piece | Bits 5-3 → File | Bits 2-0 → Rank | Chess Move |
|------------|-------------------|-----------------|-----------------|------------|
| `0x00` | `00` → ∅ | `000` → a | `000` → 1 | `a1` |
| `0x41` | `01` → N | `000` → a | `001` → 2 | `Na2` |
| `0x80` | `10` → B | `000` → a | `000` → 1 | `Ba1` |
| `0xC3` | `11` → R | `000` → a | `011` → 4 | `Ra4` |
| `0xE6` | `11` → R | `100` → e | `110` → 7 | `Re7` |
| `0xFF` | `11` → R | `111` → h | `111` → 8 | `Rh8` |

> **Formula:** `move = piece[b >> 6] + file[(b >> 3) & 7] + rank[b & 7]` — invertible, so decryption just reads the moves back into bytes.

---

## 🔓 Unlock Guide (Step-by-Step)

You received a `protected-code.html` file or a PGN snippet. Here's how to unlock it:

1. Open a `.ccx` file, paste PGN, or open a protected HTML page. In the tool, the **Unlock** tab accepts `.ccx`, PGN, and protected HTML.
2. Enter the password shared privately by the sender.
3. Click **Unlock**. The tool authenticates and decrypts the payload.
4. Encrypted files are downloaded in their original format and filename. Decrypted text is shown in the output panel.

> ⚠️ Wrong password → `Decryption failed — wrong password or data was tampered with.` The GCM auth tag catches both.

---

## 🧪 Worked Example — a real PGN you can decrypt

This PGN below was produced with the exact scheme above and **round-trip verified**. The plaintext is:

```js
// Chess Cipher demo — you unlocked me!
console.log("PGN was hiding AES-256-GCM all along.");
```

**Try it:** paste the PGN into the **Unlock** tab with password **`demo1234`** — you will get the code above back.

<details>
<summary>📜 Click to expand the full demo PGN (70 moves)</summary>

```pgn
[Event "Secret"]
[Date "2026.10.31"]
[White "?"]
[Black "?"]
[Result "*"]

1. Nb3 e7 2. Ra4 Ra5 3. Rc8 Bh3 4. Rd4 Rf1 5. Bg2 Nc8 6. f5 Nf2
7. Nd4 g4 8. Rb3 a3 9. d1 Ne3 10. Nc3 Ra7 11. g6 Ng6 12. Nc7 c4
13. Ng3 Re6 14. h4 Re4 15. Nc4 Bb4 16. a2 Re2 17. Bf6 Na5 18. c3 Ne8
19. Be5 Ne7 20. Ng3 h5 21. Rg8 Nd6 22. Rc2 Bb7 23. Nb6 Na1 24. Rh6 Nd4
25. a8 Re5 26. Bh5 Ne5 27. h6 Rf6 28. Nd6 Ng6 29. Be8 Nh8 30. Nh4 Bd3
31. g3 Ra1 32. Re5 Be4 33. g8 Bf5 34. Ra1 Bc6 35. Nd1 Ra1 36. g7 Nc2
37. Nc3 Bb4 38. Rb4 Nb7 39. Nb6 Rc7 40. Bc6 a6 41. h8 Bd5 42. Rd7 Na7
43. e3 Be7 44. c8 Nh6 45. h7 Ne6 46. c3 Na4 47. Ne7 Bf1 48. Bf3 Bb2
49. Be7 Rg3 50. Ra3 Nd3 51. Ne3 c1 52. h8 Bd7 53. b3 Ne7 54. c1 c2
55. Ra2 Bc8 56. b6 c1 57. Bh7 Na2 58. b5 Nc7 59. g7 f1 60. Ng2 Ne6
61. a7 Ne1 62. Rd1 e1 63. Ba5 Rg8 64. Rf6 Ra4 65. Bg1 Re3 66. Nc2 Ba5
67. b5 Rf4 68. Rc8 Rf5 69. Ne4 Ra2 70. Na6 e7
*
```

</details>

> Note the opening: the first 16 half-moves (`Nb3 e7 Ra4 Ra5 … a3`) are the random salt — bytes `4A 26 C3 C4 D7 BA DB E8 B1 57 2C 69 5B 33 CA 02`. That's why encrypting with the same password never produces the same game twice.

---

## 🛡️ Security Notes

- ✅ AES-256-GCM with a 128-bit authentication tag and version-bound Additional Authenticated Data (AAD)
- ✅ PBKDF2-SHA256 with 1,000,000 iterations for new CCX v3 files
- ✅ HKDF-SHA256 derives a dedicated encryption key with a domain-separated context
- ✅ Fresh random 16-byte salt and 12-byte nonce per encryption
- ✅ Random padding hides the exact plaintext length within a power-of-two size bucket
- ✅ Backward-compatible decryption for v2 (600,000 iterations) and legacy (100,000 iterations) files
- ⚠️ **No password recovery** — if lost, data is gone
- ✅ New encryptions require at least 16 Unicode characters and a matching confirmation; passwords are limited to 1,024 UTF-8 bytes.
- ⚠️ Use a unique, long passphrase and share it over a **separate channel** from the HTML/PGN
- ⚠️ Chess notation is only an encoding/obfuscation layer; the cryptographic protection comes from AES-GCM
- ⚠️ PBKDF2 is not memory-hard like Argon2id. This browser-only build uses native Web Crypto so it can work offline without loading third-party code. A future Argon2id migration should bundle and audit a maintained implementation, not fetch executable crypto code from a CDN.
- ⚠️ Treat downloaded protected HTML as executable content; open it only if you trust its source
- ℹ️ The page uses a restrictive meta CSP, but GitHub Pages does not let this repository set HTTP response security headers
- ℹ️ The cipher *disguises* traffic as chess moves — it does not hide *metadata* (message size ≈ game length)

---

## 📎 Appendix — full 256-entry mapping

Every byte → move pair in one table; amber frames mark the worked examples above.

![Full byte to move map, 256 entries](https://github.com/hieuzed06-bot/script/blob/main/image/full-mapping.png)

---

*Made with ♟️ — keep your code on the board, but off the record.*


## CCX v3 envelope

New encrypted byte streams begin with the `CCX3` magic marker, followed by a 16-byte salt, 12-byte nonce, and AES-GCM ciphertext plus its 16-byte tag. A fixed canonical AAD string binds the format version, KDF, work factor, cipher, and codec identifier. The decrypted payload starts with a 4-byte big-endian plaintext length and is padded with random bytes to the next power-of-two bucket (minimum 256 bytes). The chess move alphabet remains a reversible byte encoding and does not add cryptographic strength.

## Input limits and validation

- Text and uploaded file payloads are limited to 1 MiB after encrypted file metadata is added. Binary files are preserved byte-for-byte.
- PGN input is limited to 8 MiB and accepts only the chess-cipher move format, PGN move numbers, headers, and result markers. SAN moves, comments, variations, and malformed tokens are rejected.
- Run `npm test` locally; GitHub Actions runs the same codec test suite for pushes and pull requests.
- The main app loads JavaScript from `app.js` under a `script-src 'self'` policy. Downloaded protected pages use a fresh per-page CSP nonce for their embedded decryptor.


## Optional encrypted Mate field

The Protect tab includes an optional **Mate** field for a second secret or private note. Its UTF-8 bytes are wrapped with the selected content before encryption, so the Mate value is protected by the same AES-GCM envelope and appears only after successful decryption. It is not the encryption password. Existing encrypted files without Mate remain readable. Mate content is limited to 4 KiB, and the combined encrypted payload remains limited to 1 MiB.

The password inputs are cleared immediately after their values are read for an operation, and no password or Mate value is written to browser storage or application logs. Browser DevTools can still inspect page state while a page is running; a browser-only app cannot guarantee secrecy from someone controlling the browser or its debugging tools.
