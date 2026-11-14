# Fauna — Write-up

| | |
|---|---|
| Category | Crypto |
| Platform | Dreamhack wargame #1032 *Fauna* (65 solves) |
| Flag format | `POKA{...}` — the original CTF's format, **not** `DH{...}` |
| Files | `chal.py` (1,087 B), `values` (10,000 lines, one 512-bit integer each, 1,551,674 B), `enc` (96 B = 16-byte IV + 80-byte AES-CBC ciphertext) |

> **Mind the file name.** This challenge ships `chal.py` (one *l*). `chall.py` is a different challenge's file (#2824 *RBG+++*, a 274-bit RSA task). The two ended up in one folder while we worked on this; see [§9](#9-process-note-dont-mix-up-the-files).

`chal.py` is given in full, so there is nothing to reverse. It is all mathematics.

## TL;DR

* The generator is a **pure multiplicative LCG mod 2^1024** (no increment). Only the top 512 bits of each state are published, and each step is recorded only with probability 1/2.
* No increment means `x_{j+i} = a^i · x_j`. So any integer vector `l` with `Σ l_i · a^i ≡ 0 (mod 2^1024)` (an *annihilator* of the multiplier) kills every run of consecutive states, and the unknown low halves show up only as a small residual. A lattice built **from the public high halves alone** contains such short vectors — we never need to know `a` first.
* A window of 9 consecutive records is truly consecutive in LCG steps with probability 2^-8, so we scan windows with LLL (fpylll, ~17 ms each) until a short vector appears.
* Short vectors → an exact linear system for the 9 unknown low halves → full 1024-bit states → `a = x_{j+1} · x_j^{-1}`. Walk forward, resolving every skipped step by comparing high halves; one more step gives the key state → SHA-256 → AES-CBC.

## 1. The challenge

```python
class LCG:
    BITS, MOD, TRUNC = 1024, 2**1024, 512

    def __init__(self):
        self.mult  = int.from_bytes(urandom(128), 'big') | 1   # unknown, odd
        self.value = int.from_bytes(urandom(128), 'big')       # unknown

    def next(self):
        self.value = self.mult * self.value % self.MOD
        return self.value >> self.TRUNC                        # top 512 bits only

cnt = 0
while cnt < 10000:
    value = lcg.next()
    if urandom(1)[0] & 1:          # each step is recorded with probability 1/2
        cnt += 1
        f.write(str(value) + '\n')

key = sha256(lcg.next().to_bytes(64, 'big')).digest()   # the state AFTER the last recorded one
cipher = AES.new(key, AES.MODE_CBC, iv=urandom(16))
```

Three things are hidden at once:

| Unknown | Size |
|---|---|
| multiplier `a` | 1024 bits (odd) |
| low half of every state | 512 bits per sample |
| gap between consecutive records | Geometric(1/2), unknown each time |

No increment, truncation by exactly one half, and random gaps: together these defeat the textbook attacks, but the first one also hands us the structure we need.

## 2. Dead ends

### 2.1 Hensel / 2-adic lifting from the LSB

Write a state as `x = Y + z`, where `Y = y << 512` is the published high part and `0 ≤ z < 2^512` is the unknown low part. Reducing the recurrence mod 2^512 gives

```
z_{t+1} ≡ (a mod 2^512) · z_t   (mod 2^512)
```

The low half is a closed LCG of its own, and the observed `y` never appears in it — lifting adds unknowns but no information. The high half is no better: with `a = a0 + a1·2^512`,

```
y_{t+1} ≡ a0·y_t + a1·z_t + floor(a0·z_t / 2^512)   (mod 2^512)
```

and the carry term depends on *all* bits of `a0·z_t`, which are unknown. In 2-adic terms an "approximation" means knowing low bits; this challenge hands us the **high** bits. The direction is backwards. Real-valued approximations fail too (the truncation is exactly half, so the error is as large as the terms), and the 2-adic periodicity `a^(2^k) ≡ 1 (mod 2^(k+2))` needs ~2^510 steps to matter mod 2^512.

### 2.2 Solving the annihilator polynomial for `a`

Having `l`, it is tempting to solve `Σ l_i a^i ≡ 0 (mod 2^1024)` for `a` directly. This is fragile — see the pitfall in [§5](#5-from-short-vectors-to-states-to-the-multiplier).

## 3. Key idea: the annihilator lattice

Number the recorded samples `0, 1, …` and consider a window of samples that are consecutive in **LCG steps** (all gaps equal to 1). Because there is no increment,

```
x_{j+i} = a^i · x_j .
```

Let

```
A = { l ∈ Z^n :  Σ_i l_i · a^i ≡ 0  (mod 2^1024) } .
```

For every `l ∈ A` and every such window,

```
Σ_i l_i · x_{j+i} = x_j · (Σ_i l_i a^i) ≡ 0   (mod 2^1024)
```

independent of `j`. Substitute `x = Y + z`:

```
Σ_i l_i · Y_{j+i}  ≡  − Σ_i l_i · z_{j+i}   (mod 2^1024) .
```

The left side is entirely public. The right side is small: at most `n · max|l_i| · 2^512`. `A` has index 2^1024 in `Z^n`, so `λ1(A) ≈ 2^(1024/n)` and the right side is about `2^(1024/n + 512)` — far below 2^1024. A lattice reduction can therefore find `l`. **`a` itself is never needed**; the lattice is built from `Y` only.

### Lattice construction

Use `n` coefficient rows and `m` congruences (the same `l` is applied to `m` shifted windows, giving `m` equations). A window has length `L = n + m − 1`.

```
[ 2^512 · I_n  |  H            ]    n rows,  H[i][k] = Y_{j+k+i}
[      0       |  2^1024 · I_m ]    m rows   (these encode "mod 2^1024")
```

A lattice vector with coefficient vector `l` and reduction multiples `c` is `(2^512·l , (Σ_i l_i Y_{j+k+i} + 2^1024·c_k)_k)`. The `2^512` scale balances the two blocks.

With `n = m = 5` (`L = 9`):

| Quantity | Value |
|---|---|
| dimension | 10 |
| log2 det | 512·5 + 1024·5 = 7,680 |
| Gauss heuristic λ1 of a random lattice | 2^(7680/10) = **2^768** |
| planted vector (`l` and residual) | ≈ 2^(1024/5 + 512) = **2^716.8** |
| slack | **2^51.2** |

51 bits of slack means the decision is unambiguous. We checked both sides: reducing a window with mixed gaps (useless) gives a shortest vector of almost exactly 2^768, i.e. the Gauss heuristic; a usable window gives ≤ 2^716.8. Any threshold in between (e.g. 2^740) separates them.

General slack for block sizes `n, m` and word size `B` bits:

```
slack(B, n, m) = (B·n/2 + B·m)/(n + m)  −  (B/n + B/2)
```

For `B = 1024, n = m = 5` this is 51.2 bits (see [§6](#6-pitfall-do-not-validate-on-a-shrunken-model) for why this number matters).

## 4. The gap problem: finding usable windows

The relation `x_{j+i} = a^i x_j` needs the window's samples to be consecutive in LCG steps, not just consecutive in the file. A 9-sample window has 8 gaps, each equal to 1 with probability 1/2, so a window is usable with probability **2^-8 = 1/256**. Over 10,000 samples that is ≈ 39 usable windows in expectation.

Strategy: reduce windows one after another and stop at the first whose shortest vector falls below the threshold. A bad window returns ≈ 2^768 and is rejected at once.

Cost (fpylll, dimension 10, 1024-bit entries: **17.5 ms** per reduction):

| | fpylll | pure-Python / sympy `DomainMatrix.lll()` (13.9 s per reduction, reported) |
|---|---|---|
| expected until the first hit (~256 windows) | ≈ 4.5 s | ≈ 1 h |
| full scan of all 9,992 windows | ≈ 175 s | ≈ 38 h |

The per-reduction speed-up is roughly 800×, and it is what makes the scan practical.

Result on the real data, using the gap sequence recovered later:

```
windows of length 9 with every gap == 1 : 49   (expected 39.0)
first one                               : j = 18
first twelve                            : 18, 100, 101, 183, 857, 858, 1182, 1183, 1184, 1185, 2659, 2660
```

The scan indeed stopped at `j = 18`. That was a little lucky (P[first hit within 19 windows] ≈ 7%), not a property of the method. The excess of 49 over 39 is about 1.6σ under a naive Poisson model; usable windows come in overlapping runs (1182–1185), which inflates the variance, so we do not read anything into it.

Install note: fpylll installs without sudo, but needs `cysignals` or it dies with `No module named 'cysignals'`.

```bash
uv venv --python 3.12 /tmp/v
uv pip install --python /tmp/v/bin/python fpylll cysignals
```

## 5. From short vectors to states to the multiplier

Collect every reduced basis vector below the threshold. Each one gives a coefficient vector `l` and, for `k = 0..m−1`, the residual

```
e_k = − Σ_i l_i · z_{j+k+i}
```

which is an **exact integer equation**, not a congruence (its magnitude is far below 2^1023, so the centered residue is the true value). With two or more independent short vectors we get ≥ 10 rational equations in the 9 unknowns `z_j … z_{j+8}`; Gaussian elimination over Q fixes them. Then

```
x_t = Y_t + z_t ,        a = x_{j+1} · x_j^{-1}   (mod 2^1024)
```

### Pitfall: do not solve the annihilator polynomial for `a`

If `v = v2(x_j) > 0`, the relation `x_j · Σ l_i a^i ≡ 0 (mod 2^1024)` only forces `Σ l_i a^i ≡ 0 (mod 2^(1024−v))`. The true `a` then silently drops out of the root set of the polynomial taken mod 2^1024. The symptom is odd and worth remembering: `Σ l_i a^i ≠ 0` while `e = −Σ l_i z` is exactly right. In a 128-bit shrunken experiment it showed up as `annihilator_ok=False / e_matches=True`; a 512-bit simulation hit `v2 = 3`.

Solving the **integer equations for `z`** avoids the trap, because it does not care about the 2-adic valuation of `x_j`.

Two remarks on odd/even states:

* `a` is odd, so `v2(x_t)` is constant along the whole orbit. Whether `x_j` is invertible is a property of the instance (probability 1/2), not of the window.
* If `v > 0`, divide out `2^v` and work mod `2^(1024−v)`; any odd lift of `a` then gives the same forward walk. The root-based route (Appendix A) cannot recover from this, so its success here implies this instance has odd states. That is our inference from the fact that both routes worked.

## 6. Pitfall: do not validate on a shrunken model

Prototyping a lattice attack on small parameters is normal. Here it misleads. With `BITS = 128, n = 4, m = 8`, twelve negative controls (windows with mixed gaps) passed the threshold, as if the discriminator did not work.

The reason is that the slack is not scale-invariant. By the formula in §3:

| Parameters | slack |
|---|---|
| `BITS = 1024, n = m = 5` | **2^51.2** |
| `BITS = 128, n = 4, m = 8` | **2^10.7** |

With ~10 bits of slack, the LLL approximation factor and noise swallow the gap. "Cannot discriminate" in the small model was a failure of the model, not of the attack. Compute the slack first and test at a size where it stays comfortable (here `BITS ≥ 512`).

## 7. Gap resolution, key, and decryption

Given `a` and one full state, everything else is mechanical. Step the state forward one LCG step at a time and compare its high 512 bits with the next unread record: equal means "recorded", different means "skipped". A false match at 512 bits is negligible, so every gap is recovered deterministically.

After the last (10,000th) record, call `next()` once more — that is what `chal.py` does:

```python
key_state = (state * a) % 2**1024          # one step PAST the last record
key = sha256((key_state >> 512).to_bytes(64, 'big')).digest()
blob = open('enc', 'rb').read()            # read(), not readline(): binary data may contain 0x0a
iv, ct = blob[:16], blob[16:]
print(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct))
```

The key comes from the state **after** the last recorded value, not from the last record itself. Missing that step is the easiest mistake here, and two of the negative controls in §8 test exactly that.

## 8. Verification

We have no oracle (the flag *is* the decryption result), so we cross-checked three independent ways. Everything below was measured with the distributed files and the recovered `(a, x_18)`.

**(a) Reproduction without the lattice.** From the recovered state at sample 18, walk backwards (42 LCG steps) to sample 0, then forward again over the whole file:

```
from sample 18 backwards : 42 steps → reaches sample 0
from sample 0 forwards   : 19,681 steps
published values matched : 10,000 / 10,000
```

One wrong bit in `a` breaks this within the first few steps, so this single check pins down `a` and the whole state sequence.

**(b) Gap distribution against theory.** The recovered gaps are a by-product that is only right if the algorithm is right (9,999 gaps):

| gap | count | observed | Geometric(1/2) |
|---|---|---|---|
| 1 | 5,150 | 51.51 % | 50.00 % |
| 2 | 2,444 | 24.44 % | 25.00 % |
| 3 | 1,204 | 12.04 % | 12.50 % |
| 4 | 590 | 5.90 % | 6.25 % |
| 5 | 293 | 2.93 % | 3.13 % |
| 6 | 168 | 1.68 % | 1.56 % |

(The remaining 150 gaps are ≥ 7. Their sum with the table gives ≈ 19.7k steps, consistent with the 19,681 in (a).)

**(c) Decrypted structure plus negative controls.**

```
PKCS#7 padding        : valid (padlen = 16)
plaintext length      : 64 bytes
all printable ASCII   : True
embedded NUL          : none
prefix / suffix       : POKA{ ... }
```

A 64-byte flag plus a full 16-byte padding block is exactly the 80-byte ciphertext in `enc`. Four wrong key states all fail:

| Wrong key state | padding_ok | printable |
|---|---|---|
| one step early (the last published state) | False | False |
| one step late | False | False |
| random 512 bits | False | False |
| the last published value used directly | False | False |

**(d) Synthetic data with known truth.** The same script run with `--sim 512` on a generator of the same structure matched the true multiplier and key state (`a matches truth: True`, `key state matches truth: True`).

## 9. Process note: don't mix up the files

Two challenges' files were in one folder, one letter apart:

```
chal.py    1,087 B   1024-bit multiplicative LCG + AES-CBC     ← this challenge (#1032)
chall.py     389 B   RSA with LCG-generated exponents          ← a different challenge (#2824)
```

In hindsight the cheapest discriminator was the timestamps. One challenge's files are produced together and ship in one archive, so they share an mtime. Here the files fell into two groups (2023-09-19 for this challenge versus 2026-04-02 for the other), visible with a single `ls -la` before reading any content.

A second lesson: an early guess about what the challenge title meant ("RBG = Random Bit Generator") was used to rule out a candidate file. The ruling-out was based on a title, not on data. Two people independently picked the same file, which felt like confirmation but was not — they shared the same assumption. **Independence has to be of assumptions, not of people.** Here the answer happened to be right (a flag came out); the label could easily have been wrong, and a wrong label means a wrong submission.

## 10. Takeaways

Three defenses, each reasonable alone, together still break:

| Defense | What it blocks | Why it is not enough |
|---|---|---|
| publish only the top 512 bits | reading the state directly | the annihilator relation absorbs the unknown low half as a small residual |
| hide the multiplier | using the recurrence | the annihilator lattice is built without `a` |
| record each step with probability 1/2 | consecutive relations | usable windows exist with probability 2^-(L−1), and 10,000 samples yield ~40 of them |

Design observations:

* A pure multiplicative LCG keeps the algebraic structure `x_{j+i} = a^i x_j`. With an increment, the annihilator relation would gain a constant term and the lattice one more dimension, shrinking the slack.
* Truncating exactly half looks safest because it seals the LSB-lifting route (the low half is self-contained), but it leaves the lattice route fully open. Closing one direction fully while leaving another open is the typical failure.
* Random skipping only costs a constant factor. Skipping with probability 15/16, or publishing far fewer samples, would drive the expected number of 9-sample windows to ~0 and would actually have been a defense. 10,000 samples is too generous.
* Deriving the key from the state *after* the last record is a good choice: published values alone never reach it without recovering the multiplier.

Rules for the analyst:

1. Given the **top** bits of a truncated LCG, abandon 2-adic lifting; build a lattice.
2. Do not try to find the multiplier first. The annihilator relation holds with the multiplier eliminated; `a` falls out of one division after the states are known.
3. Prefer exact integer equations for the low halves over solving for `a` as a polynomial root.
4. Compute the slack before shrinking a lattice experiment.

## 11. Caveats

* `n = m = 5` is "enough", not optimal. A larger `n` shortens the window (higher hit rate) at the cost of slack; a smaller `n` buys slack. We did not search the trade-off. With `L = 7` instead of 9 there would be ~4× as many usable windows.
* The 49-vs-39 excess in usable windows was not tested beyond the 1.6σ naive estimate. The gap histogram matches theory, so we have no reason to suspect `urandom` bias.
* The slack figures (§3, §6) and the scan-cost estimates (§4) are computed from the block sizes and per-reduction timings stated there. The measured results in §4 and §8 come from runs on the real files.

## Appendix A. Original solver path (Coppersmith attempts, then Frieze–Håstad–Kannan–Lagarias–Shamir)

This is how the problem was actually first solved, before the cleaner annihilator view above. It uses the same lattice as §3 but extracts `a` differently.

### A.1 Coppersmith on three consecutive states (ePrint 2021/1204)

Write the three states as `v_i = H_i + δ_i` (`H_i` known high part, `δ_i < 2^l` unknown low part). From `v1² = v0·v2 (mod 2^n)`:

```
P(y0,y1,y2) = y1² − y0·y2 + 2H1·y1 − H0·y2 − H2·y0 + H1² − H0·H2  ≡ 0   (mod 2^n)
```

The monomials are `{y0, y1, y2, y1², y0y2}`, so the Coppersmith bound `(2^l)^7 < 2^n` fails for `l = n/2` and many more equations are needed. The paper's second variant uses two pairs of consecutive states `(v_i, v_{i+1})`, `(v_j, v_{j+1})`. We generalized it to pairs with equal index difference `k` and confirmed the bound on paper, but the implementation never produced a correct solution, and we did not find why.

Two heuristics were tried on top:

1. Pick `n` random samples whose multiplier relation matches by chance and run LLL until some subset works — combinatorially hopeless; too many cases tried, no correct value.
2. Assume 9–10 consecutive outputs and run Coppersmith on them (`CONSECUTIVE_NUM = 9`) — monomial counts looked right, but the solutions never came out.

### A.2 What worked: window lattice + Hensel roots + voting

For each window of 9 records, build the §3 lattice (`r = 5`), take the first reduced row as a polynomial `f(X) = Σ (row_i / 2^512) · X^i`, and find its roots mod 2^1024 by Hensel lifting. Bad windows produce junk roots; good windows all contain the true multiplier, so a vote over many windows returns it:

```python
for i in range(r):
    for j in range(r):
        B[i][j] = HALF_MOD * li[a + i + j]   # Hankel block of Y = y << 512
# M = [[2^512·I, B], [0, 2^1024·I]]
row = LLL(M)[0]
f = sum(R(row[i] // HALF_MOD) * X**i for i in range(r))
for root in hensel_roots(f, 2, 1024):
    votes[root] += 1                          # the true multiplier collects votes from good windows
mult = argmax(votes)
```

This is the root-based route from §5: it silently relies on the states being odd. It happened to hold here.

### A.3 State recovery with a known multiplier (Frieze et al.)

Once `a` is known, the annihilator lattice can be written down explicitly and used as a CVP/rounding step:

```python
def attack(y, k, s, m, a, c):
    """y: truncated outputs (top s bits of k-bit states), m: modulus, a: multiplier, c: increment (0 here)."""
    diff_bit_length = k - s
    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        y[i] = (y[i] << diff_bit_length) - delta
        delta = (a * delta + c) % m

    B = matrix(ZZ, len(y), len(y))            # basis of the annihilator lattice of a
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1
    B = B.LLL()

    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]  # centered residues = exact low-half combinations

    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m
    return x
```

(Basis rows `(m,0,…,0)` and `(a^i, 0,…,−1,…,0)` generate `{u : Σ u_i a^i ≡ 0 mod m}` — the same annihilator lattice as §3, now with `a` known.) It needs 8 truly consecutive samples as input; the original run used the window starting at index 9770.

### A.4 Finishing

```python
ans = attack(li[count:count + 8], 1024, 512, MOD, mult, 0)
val = ans[0]
while count != 9999:
    val = val * mult % MOD
    if val >> 512 == li[count + 1]:   # equal -> that step was recorded; otherwise it was skipped
        count += 1
val = val * mult % MOD                # one more step: the key state
key = sha256((val >> 512).to_bytes(64, 'big')).digest()
print(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct))
```

## Flag

```
POKA{...}
```

## References

* Frieze, Håstad, Kannan, Lagarias, Shamir — *Reconstructing Truncated Integer Variables Satisfying Linear Congruences* (the lattice used in `attack()`).
* ePrint 2021/1204, §3 "Attacks on the Linear Congruential Generator" (Coppersmith-style attacks, Appendix A.1).
