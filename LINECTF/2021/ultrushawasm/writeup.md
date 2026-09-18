# LINE CTF 2021 — ultrushawasm

pwn / WASM+Rust, solved via the intentional panic-hook backdoor.

Flag : 

```
DH{3c65d0****************************96a11b}
```

## The setup

You connect to a service that pretends to be a `root@ultrasecure` SSH-style login: it asks for a password, then walks you through a fake 2FA flow (push notification or SMS code), and if you get through, it tries to hand you a shell. Under the hood it's all one `world.wasm` binary compiled from Rust and run with `wasmtime --dir=. world.wasm`.

The challenge description more or less tells you there's a bug in the login: typing `1234` gets you past the password prompt when it shouldn't. That's the "mistake" they mention. It's not the actual vuln, though — it's just the door that lets you reach the code that is.

I pulled the binary apart with `wasm2wat` and wabt's `wasm-decompile` to get something readable out of it.

## How the login actually works

Once you're past the password, you get:

```
1. Push to +XX XX-XXXX-1337
2. SMS passcodes to +XX XX-XXXX-1337 (next code starts with: 1)
```

Picking `1` goes down a separate path that never touches the flag. Picking `2` calls into a function I ended up calling `setup_magic()` (that's literally the mangled name it demangles to), and this is where the flag actually gets used:

1. It reads `/flag` into a `String`.
2. It hashes `SHA256(flag_bytes + current_timestamp)` and stashes the 32-byte digest in a fixed global at `0x104170` (`1066160`). That digest is effectively "the correct SMS code" — the UI just leaks you its first hex nibble as a taunt (`next code starts with: 1`).
3. When you type your guess at the `Verification Code:` prompt, it XORs every byte of your input with `0x41` into a fixed 32-byte scratch buffer at `1066192`, hashes `SHA256(xored_input + SALT)`, and compares that against the digest from step 2.
4. Here's the bug: the destination buffer for that XOR loop is exactly 32 bytes, but the loop doesn't check that against the buffer's own bound — only against your input length. Send 32+ characters and it happily writes to index 32, and you get:

   ```
   thread 'main' panicked at 'index out of bounds: the len is 32 but the index is 32', src/main.rs:269:26
   ```

If you'd somehow guessed the right code, you'd reach `authorized()`, which tries to `Command::new("sh").spawn()` — which fails inside the WASI sandbox and panics too, with a different message. That path is unreachable without knowing the code, so it's not the intended route in.

## The actual backdoor

This challenge's twist is that the default panic hook has been backdoored. Digging into `std::panicking::default_hook`'s closure, there's extra logic bolted onto it that doesn't belong there:

```
BASE = len(panic_message) * 19418
if MEM[BASE + 20090 .. BASE + 20094] == b"lock":
    ptr = horner_decode(MEM[BASE + 20094 .. BASE + 20118]) - 805306320
    leak 15 bytes starting at ptr        # dumped to stderr, one 4-byte hex word per line
```

`BASE` only depends on the *length* of whichever panic message actually fires — for our bounds-check panic that string is always the same 54 bytes, so `BASE = 54 * 19418 = 1048572` and the address it checks is `1048572 + 20090 = 1068662`.

The 24 bytes after the `"lock"` marker encode a 32-bit pointer with a little Horner scheme — weights `1 << (23-i)`, each byte greedily picked in `0..=255`. To point it at address `P` you encode `(P + 805306320) & 0xFFFFFFFF`:

```python
def solve_bytes(target):
    target &= 0xFFFFFFFF
    weights = [1 << (23 - i) for i in range(24)]
    remaining = target
    out = [0] * 24
    for i in range(24):
        w = weights[i]
        b = min(remaining // w, 255)
        out[i] = b
        remaining -= b * w
    assert remaining == 0
    return bytes(out)
```

So: any panic in this program is potentially a 15-byte arbitrary read, gated on nothing more than getting the 4 bytes `"lock"` sitting at the right address when it happens.

## Getting the sentinel in place

The `Verification Code:` string always lands at heap address `1068144` — I confirmed this is stable in local `wasmtime` runs *and* on the real remote box, which makes sense once you remember the allocator is compiled into the wasm module itself rather than provided by the host, so it behaves identically no matter what's running it.

`1068662 - 1068144 = 518`. So: send a code that's at least ~546 bytes long, put `b"lock"` at offset 518 and the 24 Horner bytes right after it, and the check passes. (546+ bytes also satisfies the ≥32 requirement for the bug to fire in the first place, for free.)

## The part that actually took a while: the flag kept getting eaten

Once I had the lock check reliably passing, I pointed it at the address where the flag gets loaded and got... garbage. Mostly. A few readable bytes surrounded by what was clearly heap metadata (pointers, lengths, zeros).

Turns out the `String` that held the flag gets dropped once `setup_magic()` returns, so it sits on the free list. Then, while processing *my own* verification-code input — reading it into a fresh `String`, running it through the XOR/SHA comparison — the allocator reuses that exact freed block. Doesn't matter what I send, short or long, valid-looking or not: by the time the panic fires, most of the flag's old memory has already been stomped on.

Leaking that address directly (both locally and against the real server, same result) showed this pattern:

```
+0  .. +11   overwritten
+12 .. +19   untouched (8 clean bytes)
+20 .. +31   zeroed
+32 .. +35   untouched (4 clean bytes — "eebb")
+36 .. +39   zeroed
+40 .. +43   untouched, ends in '}' (4 clean bytes — "...11b}")
```

So the backdoor genuinely worked, but the only path I had to trigger it also wrecked the thing I was trying to read.

## The fix: groom the heap first

The option-selection prompt (`1` or `2`) only looks at the first character of what you send — everything after it is thrown away. But it still gets read into its own heap-allocated `String` first. Pad that line out to something absurd, like `"2" + "B"*1999`, and every allocation that happens afterward — including the flag's `read_to_string` buffer — gets pushed way further down the heap, past anywhere the verification-code comparison logic ever reaches.

I checked this locally across a few padding sizes:

| option-line length | flag ends up at | flag after submitting a code |
|---|---|---|
| 1 (no padding) | `1046660` | mangled, ~8 bytes survive |
| 500 | `1076960` | untouched |
| 2000 | `1078464` | untouched |
| 10000 | `1092848` | untouched |

With 2000 bytes of padding, the flag consistently lands at `1078464` — and this held regardless of the flag's own length in my local tests (tried mock flags from 20 to 120 bytes), which makes sense since its position is determined by everything allocated *before* it, not its own size.

## Putting it together

1. Connect.
2. Send `1234\n`.
3. Send `"2" + "B"*1999 + "\n"` — this triggers `setup_magic()` and grooms the heap in the same step.
4. As the verification code, send a 600-byte buffer with `"lock"` at offset 518 and the Horner-encoded pointer to `1078464` right after it.
5. The bounds-check panic fires, the backdoor's lock check passes, and 15 bytes starting at `1078464` come back over stderr as hex.
6. Since the flag is longer than 15 bytes, repeat with a few more targets (`1078464 + 14*i`) over separate connections and stitch the overlapping little-endian reads back together.

I ran this for real against `host3.dreamhack.games` (through a GitHub Actions job, since this environment's own egress is locked down to port 443) and it came back clean — no garbage, no gaps, just the flag. The tail end of it matched byte-for-byte with the `"...11b}"` fragment that had survived the *un-groomed* leak earlier, which was a nice sanity check that this wasn't a fluke.

## Constants, for anyone reproducing this

| name | value |
|---|---|
| `__heap_base` | `1066900` |
| SHA256 salt (34 bytes, at `1050996`) | `XJrjzrBMmL5LrzxKizxZ4P3qR4UiSD6c21` |
| static hash string in the data section (at `1076416`, matches on the real server too) | `E432692E938DCF4415A8B58B56359DA9DAC76A1C4566DCC89E0D8132C7D78C92` |
| verification-code buffer address | `1068144` |
| backdoor lock-check address | `1068662` |
| flag address (with 2000-byte grooming) | `1078464` |

## tl;dr

- Real bug: missing bounds check in the 2FA code comparison (`src/main.rs:269`), triggered by a code ≥ 32 chars.
- The actual "vulnerability" you're meant to find, though, is the backdoored panic hook — any panic can leak 15 arbitrary bytes if you plant a `"lock"` marker + Horner-encoded pointer at a predictable address.
- The naive version of the exploit destroys the flag before it can read it, as an unavoidable side effect of processing your own input.
- Padding the earlier option-selection input grooms the heap so the flag ends up somewhere the destructive path never touches — after that, the leak is clean.

## Files

- `scripts/exploit.py` — final PoC: grooms the heap, fires 14 overlapping leak requests at the flag's address, and reassembles the result.
- Local development used the `wasmtime` Python bindings and wabt (`wasm2wat`, `wasm-decompile`) against the unmodified binary, with a stand-in `/flag` so the whole trigger → groom → leak pipeline could be validated before pointing it at the real server.
