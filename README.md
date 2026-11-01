# 🔐 Code Locker — Chess Cipher v2

> **Creative Chess Notation Encryption** — turn any source code into a PGN chess game record that still decrypts with AES-256-GCM.

---

## ✨ What It Does

`Code Locker` disguises encrypted source code as a **real-looking chess game record**. Behind the board: **AES-256-GCM** + **PBKDF2-SHA256 (100,000 iterations)**. The output is either a PGN text or a self-contained HTML page — recipients just open it, enter the password, and the code is revealed.

| | |
|---|---|
| 🔒 **Protect tab** | paste code + password → get PGN / self-decrypting HTML |
| 🔓 **Unlock tab** | paste PGN (or protected HTML) + password → get code back |
| 🌐 **Any language** | JS, Python, C, SQL… everything is UTF-8 bytes first |

---

## 🔐 How to Encrypt (Protect tab)

![Encryption pipeline](https://raw.githubusercontent.com/hieuzed06-bot/script/main/image/encryption-flow.png)

1. **Open `Code Locker — Chess Cipher v2.html`** in any modern browser. Stay on the **🔒 Protect code** tab.
2. **Paste your source code** into the *Source code* box — the counter shows lines and size.
3. **Type a strong password.** ⚠️ There is **no password recovery** — lose it and the data is gone.
4. **Click `🔐 Encrypt`.** The tool runs PBKDF2 → AES-256-GCM → chess encoding and shows the **PGN output**.
5. **Share it** two ways:
   - **Copy** the PGN text and paste it anywhere (chat, email, README…), or
   - **Download protected page** — a single `protected-code.html` that decrypts itself in the recipient's browser.

Every encryption uses a **fresh random salt + IV**, so encrypting the same code twice gives two completely different chess games.

---

## ♟️ How Bytes Become Moves

Every byte (0–255) maps to a chess move via 4 piece groups × 8 files × 8 ranks = **256 slots**. The two high bits pick the *piece board*, three middle bits pick the *file*, three low bits pick the *rank*:

![Four chess boards showing byte ranges](https://raw.githubusercontent.com/hieuzed06-bot/script/main/image/chess-board-mapping.png)

### Byte anatomy — one worked example

![Byte 0xC3 breaks into piece, file, rank](https://raw.githubusercontent.com/hieuzed06-bot/script/main/image/byte-anatomy.png)

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

1. **Open the file** — double-click `protected-code.html`. It opens in any modern browser (Chrome, Firefox, Safari, Edge). No internet needed. *Or* open the tool's **🔓 Unlock** tab and paste the PGN.
2. **Enter the password** — the one the sender shared with you privately. There is no fallback key: an empty password is refused.
3. **Click `🔓 Unlock`.** PBKDF2 derives the AES key, GCM verifies the auth tag.
4. **See the code** — it appears in the panel. Hit **Copy code** to grab it.

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

- ✅ AES-256-GCM (authenticated encryption — tamper detection)
- ✅ PBKDF2-SHA256, 100,000 iterations (brute-force resistant)
- ✅ Random 16-byte salt + 12-byte IV per encryption (never reused)
- ⚠️ **No password recovery** — if lost, data is gone
- ⚠️ Keep the HTML file and the password on **separate channels** when sharing
- ℹ️ The cipher *disguises* traffic as chess moves — it does not hide *metadata* (message size ≈ game length)

---

## 📎 Appendix — full 256-entry mapping

Every byte → move pair in one table; amber frames mark the worked examples above.

![Full byte to move map, 256 entries](https://raw.githubusercontent.com/hieuzed06-bot/script/main/image/full-mapping.png)

---

*Made with ♟️ — keep your code on the board, but off the record.*
