# Brainfook

## 1. Target

The challenge is a custom interpreter written in Python. The actual payload is not conventional machine code; it is a program for a Brainfuck-derived VM named **BrainfOok**.

The VM exposes:

* 4 general-purpose registers
* 96 memory cells
* 2 × 32-bit bit-memory banks
* 2 independent unbounded stacks
* a register pointer
* a memory pointer
* a zero flag
* a backtracking/jump mechanism

The VM implements 25 instructions. The relevant instruction semantics are:

```text
+ -      increment/decrement current register
< >      move register pointer
]        set memory pointer from current register
{ }      load/store memory
?        set zero flag
!        conditional backtrack
# ( )    calculated relative jump
: .      input/output
$ @ [    bit-memory push/pop/bank switch
^ & | ~  bitwise operations
,        clear low bits
*        clear bits above an index
%        terminate
```

The important observation is that registers and ordinary memory are backed by Python integers, so they are not naturally 8/16/32-bit values. Only the bit-memory banks have an explicit 32-bit representation.

---

# 2. VM Semantics First

Trying to reverse the payload directly is a mistake.

There is no useful way to interpret something like:

```text
!>{!>+<-?;<-?;
```

until the semantics of `!`, `>`, `{`, `+`, `<`, and `?` are known.

The first task was therefore to reconstruct the VM in Python.

A useful abstraction is:

```python
class VM:
    regs = [0, 0, 0, 0]
    reg_ptr = 0

    mem = [0] * 96
    mem_ptr = 0

    bitmem = [
        [0] * 32,
        [0] * 32,
    ]

    bit_bank = 0

    zero = False

    # independent stacks
    stack0 = []
    stack1 = []
```

The exact implementation details depend on the original interpreter, but this abstraction is enough to reason about the payload.

---

# 3. Arithmetic Is Implemented as Loops

The VM has no multiplication, division, or comparison instructions.

Everything is synthesized from:

```text
+
-
<
>
?
!
{
}
```

For example, resetting a register to zero is essentially:

```text
!-?;
```

The loop repeatedly decrements until `?` observes zero.

Similarly, addition can be synthesized by repeatedly transferring one register into another:

```text
!<+>-?;
```

Conceptually:

```python
while r1 != 0:
    r0 += 1
    r1 -= 1
```

Multiplication uses nested loops:

```text
!>{!>+<-?;<-?;
```

which can be recognized as:

```python
result = 0

while multiplier:
    while multiplicand:
        result += 1
        multiplicand -= 1

    multiplier -= 1
```

The actual implementation has to preserve the original operands, so the real instruction sequence is more involved.

The important reversing technique is to replace repeated BrainfOok idioms with semantic operations.

For example:

```text
!>{!>+<-?;<-?;
```

should be mentally lifted from:

```text
instruction-level loop
```

to:

```python
mul(a, b)
```

The challenge contains similar templates for addition, multiplication, division, and shifts.

---

# 4. Infinite Loops Are Part of the Checker

One unusual property of the VM is that Python integers do not wrap around.

Therefore:

```text
-1
-2
-3
...
```

can continue forever.

This is important because the challenge uses non-termination as a failure mechanism.

Conceptually:

```python
if check_failed:
    while True:
        ...
```

is used instead of:

```python
return False
```

This means that a symbolic model must preserve the difference between:

```text
valid
invalid
non-terminating
```

rather than assuming every branch eventually returns.

---

# 5. Stripping the Payload

After removing the outer encoding/encryption layers, the payload contains a huge amount of junk.

The VM ignores unsupported characters, so the first normalization step is:

```python
VALID = set("+-<>][{}?!#():.$@[^&|~, *%")

code = "".join(c for c in encoded if c in VALID)
```

The exact filtering set should of course match the interpreter.

This already removes a large amount of noise.

The remaining obfuscation relies heavily on algebraic cancellation.

Examples:

```text
+-
<>
<<<< >>>>
[[
```

have either zero net arithmetic effect or restore the original pointer state.

Thus:

```text
+++++-----
```

can be lifted to:

```python
NOP
```

and:

```text
<<>>
```

can also be removed when no intermediate state is observed.

---

# 6. Do Not Naively Deobfuscate `#()`

The dangerous instruction is:

```text
#()
```

because its target is not necessarily a fixed instruction index.

The payload constructs an offset and combines it with the position of a `()` marker.

Consequently:

```text
remove junk
    ↓
instruction positions change
    ↓
() position changes
    ↓
jump target changes
    ↓
program semantics change
```

So global regex-based cleanup is unsafe.

The correct approach is to trace executed jump markers first.

The recovered offsets include values such as:

```python
o_1_s
o_2_s
o_4_s
o_9_z
o_13_z
o_14_z
o_15_z
o_32_z
o_36_z
o_38_z
```

and larger offsets used by the major control-flow blocks.

I treated regions participating in dynamic jumps as immutable while performing local simplification elsewhere.

---

# 7. Recovering the Program Structure

After deobfuscation, the payload naturally separates into stages:

```text
music / VM reset
        ↓
print banner
        ↓
read 32 bytes
        ↓
adjacent-byte check
        ↓
ASCII check
        ↓
fixed-character checks
        ↓
TEA-like stage #1
        ↓
cross-byte arithmetic checks
        ↓
TEA-like stage #2
        ↓
TEA-like stage #3
        ↓
additional arithmetic constraints
        ↓
4 × 7 matrix check
        ↓
final accumulator check
        ↓
success output
```

The source itself can be segmented into these blocks.

---

# 8. Input Handling

The input stage constructs the constant:

```python
32
```

and then reads exactly 32 bytes:

```python
m = bytearray(b"?" * 32)
```

The relevant high-level behavior is:

```python
for i in range(32):
    m[i] = read_byte()
```

This gives us the fundamental symbolic representation:

```python
m[0:32]
```

Everything after this point operates on those 32 symbolic bytes.

---

# 9. First Structural Constraints

The first validation loop checks neighboring characters.

Recovered pseudocode:

```python
for i in range(len(m) - 1):
    assert m[i] != m[i + 1]
```

The BrainfOok implementation loads:

```text
m[i]
m[i + 1]
```

subtracts them, and uses the zero flag to detect equality.

Therefore, the first constraint is simply:

```python
m[i] != m[i + 1]
```

for:

```python
0 <= i < 31
```

This is useful as a global constraint but does not reveal individual bytes by itself.

---

# 10. Printable Range

The next block establishes that every byte is at most `126`.

The VM uses a countdown comparison because there is no native comparison instruction.

Equivalent form:

```python
for c in m:
    assert c <= 126
```

The internal bookkeeping uses:

```text
memory[32] -> comparison value
memory[33] -> successful-character count
memory[34] -> current index
memory[35] -> total length
```

If the comparison cannot terminate correctly, the VM enters a failure loop.

The recovered model is:

```python
for i in range(32):
    assert m[i] <= 126
```

---

# 11. Direct Character Constraints

Several bytes are constrained through deliberately indirect arithmetic.

### Position 26

```python
assert m[26] // 5 - 19 == 0
```

### Position 21

```python
assert m[21] == m[26]
```

### Position 18

```python
assert m[18] // 19 - 5 == 0
```

### Position 12

```python
assert m[12] == (32 * 4 - 1) ^ 32
```

These are much easier to solve after lifting the BrainfOok loops into Python expressions.

The important point is that these are not approximate interpretations—the corresponding arithmetic relationships are directly recoverable from the VM code.

---

# 12. CRT Constraint

Position 4 uses a particularly clean mathematical construction:

```python
assert m[4] % 7 == 4
assert m[4] % 11 == 7
assert m[4] % 13 == 4
```

The challenge implements modulo using repeated subtraction.

Instead of emulating that code symbolically, it is much simpler to solve:

```python
for c in range(32, 127):
    if c % 7 == 4 and c % 11 == 7 and c % 13 == 4:
        print(c)
```

The three congruences uniquely identify the intended printable value.

This is a good example of why translating VM instructions into mathematical constraints is preferable to continuing with raw instruction emulation.

---

# 13. First TEA-Like Block

The first cryptographic block consumes:

```text
m[0]
m[1]
m[2]
m[3]
```

and packs them into two 16-bit words:

```python
x = m[0] + (m[1] << 8)
y = m[2] + (m[3] << 8)
```

The constants recovered from the VM are:

```python
rounds = 17
delta = 0xB941

k = [
    0x46BE,
    0x7286,
    0x8D79,
    0xD437,
]
```

The round loop lifts cleanly into:

```python
for _ in range(17):
    s += delta

    y = (
        y
        + (
            ((x << 3) + k[0])
            ^ (x + s)
            ^ ((x >> 2) + k[1])
        )
    ) & 0xFFFF

    x = (
        x
        + (
            ((y << 1) + k[2])
            ^ (y + s)
            ^ ((y >> 4) + k[3])
        )
    ) & 0xFFFF
```

The 16-bit masking is important here.

Although ordinary VM integers are unbounded, the cryptographic state is explicitly reduced to 16 bits by the bit-memory operations.

The resulting transformation is structurally similar to TEA but should be treated as a custom TEA-like construction rather than standard TEA.

---

# 14. First TEA Post-Checks

The resulting `x` and `y` are not simply compared with hardcoded ciphertext.

Instead, the checker uses arithmetic identities:

```python
assert 84 - (delta - x) == 1
```

and:

```python
assert (y ^ k[0]) - k[1] - 1170 == 9
```

Additional input bytes are then mixed into the verification.

A representative recovered constraint is:

```python
assert (
    (
        ((m[22] << 7) + m[24] + 6) * m[25]
    )
    ^ ((y + s) // 2)
    ^ ((y << 1) + k[2])
) == 2228
```

There is also a multiplicative constraint:

```python
assert m[19] > m[20]
```

followed by a relation involving:

```python
m[19] * m[20]
```

Since the operands are printable bytes, the search space is tiny once the product is known.

---

# 15. Second TEA-Like Block

The second stage begins by chain-XORing two regions.

Forward direction:

```python
for i in range(5):
    m[13 + i] ^= m[13 + (i + 1) % 5]
```

Reverse direction:

```python
for i in range(5):
    m[31 - i] ^= m[31 - (i + 1) % 5]
```

The resulting values are used to construct:

```python
x = m[30] + (m[31] << 6)
y = (m[29] + 4) * m[28]
```

The stage uses:

```python
rounds = 31
delta = 0x8F4F
```

and the custom round function is:

```python
for _ in range(31):
    s += delta

    y = (
        y
        + (
            (x * 5 + k[0])
            | ((x + s) & ((x >> 3) + k[1]))
        )
    ) & 0xFFFF

    x = (
        x
        + (
            (y * 7 + k[2])
            | ((y + s) & ((y >> 5) + k[3]))
        )
    ) & 0xFFFF
```

This is significantly different from standard TEA.

The important reversing decision here is to reproduce the exact recovered arithmetic instead of attempting to identify the algorithm by name.

---

# 16. Third TEA-Like Block

The second stage's key is transformed into a third-stage key:

```python
k = [
    k[0] ^ k[2],
    k[1] & k[3],
    k[0] | k[3],
    k[1] ^ k[2],
]
```

The delta is complemented:

```python
d = (~d) & 0xFFFF
```

The round count becomes:

```python
rounds = 23
```

The input packing changes direction:

```python
y = (m[16] << 8) + m[15]
x = (m[13] << 8) + m[14]
```

The round function becomes:

```python
for _ in range(23):
    s -= d

    y = (
        y
        + (
            (x * 3 + k[0])
            ^ (x + s)
            ^ (~((x >> 1) + k[1]))
        )
    ) & 0xFFFF

    x = (
        x
        + (
            (~(y * 13 + k[2]))
            ^ (y + s)
            ^ ((y >> 3) + k[3])
        )
    ) & 0xFFFF
```

The corresponding checks include:

```python
assert (
    m[0]
    + m[1]
    - (d // 10 - (x - k[2]) // 2)
) == 5

assert m[3] - (y // 4 + 2) // 9 == 4
```

---

# 17. Cross-Byte Constraints

The cryptographic stages are tied together by ordinary arithmetic constraints.

For example:

```python
assert m[17] < m[27]

assert (
    m[2]
    - (m[17] * m[27] - 2 * 1266)
) == 6
```

This means that bytes which are not directly involved in the same cryptographic operation can still constrain one another.

At this point, treating every byte independently is no longer practical.

The correct model is a single constraint system:

```text
m[0] ... m[31]
   │
   ├── local character constraints
   ├── arithmetic constraints
   ├── TEA #1
   ├── TEA #2
   ├── TEA #3
   └── matrix equations
```

---

# 18. Matrix Check

The remaining seven-byte block is:

```python
v = m[5:12]
```

The checker constructs:

```python
mat = [
    [52, 12, 54, 39,  5, 28, 14],
    [ 2, 23, 60, 27, 38,  6, 62],
    [12, 52,  2, 14,  8, 27, 47],
    [ 7, 34, 29, 48,  6,  4, 40],
]
```

and computes:

```python
out = [0, 0, 0, 0]

for i in range(7):
    for j in range(4):
        out[j] += mat[j][i] * m[5 + i]
```

Equivalently:

```text
out = M · v
```

where:

```text
M ∈ Z^(4×7)
v ∈ Z^7
out ∈ Z^4
```

The four resulting values are constrained by:

```python
assert 1268 * 10 - out[3] == 3

assert (
    1268
    - (out[3] - out[2]) * 3
    - 2
) // 12 == 11

assert (
    (out[1] - 1268 * 11 - 7)
    // 15
    // 4
) == 5

assert (
    (out[0] - 1268 * 13 - 2)
    // 15
    // 6
) == 6
```

The original BrainfOok implementation performs the matrix multiplication through repeated-addition loops. Once lifted, it is simply integer linear algebra.

---

# 19. Final High-Level Model

After translating the entire checker, the core can be represented approximately as:

```python
m = bytearray(b"?" * 32)

# -------------------------
# Basic constraints
# -------------------------

for i in range(31):
    assert m[i] != m[i + 1]

for i in range(32):
    assert m[i] <= 126


# -------------------------
# Character constraints
# -------------------------

assert m[26] // 5 - 19 == 0
assert m[21] == m[26]
assert m[18] // 19 - 5 == 0
assert m[12] == (32 * 4 - 1) ^ 32

assert m[4] % 7 == 4
assert m[4] % 11 == 7
assert m[4] % 13 == 4


# -------------------------
# TEA-like stage 1
# -------------------------

x = m[0] + (m[1] << 8)
y = m[2] + (m[3] << 8)

s = 0
d = 0xB941

k = [
    0x46BE,
    0x7286,
    0x8D79,
    0xD437,
]

for _ in range(17):
    s += d

    y = (
        y
        + (
            ((x << 3) + k[0])
            ^ (x + s)
            ^ ((x >> 2) + k[1])
        )
    ) & 0xFFFF

    x = (
        x
        + (
            ((y << 1) + k[2])
            ^ (y + s)
            ^ ((y >> 4) + k[3])
        )
    ) & 0xFFFF


assert 84 - (d - x) == 1
assert (y ^ k[0]) - k[1] - 1170 == 9


# -------------------------
# Cross-byte constraints
# -------------------------

assert m[19] > m[20]

# ...


# -------------------------
# Stage 2
# -------------------------

for i in range(5):
    m[13 + i] ^= m[13 + (i + 1) % 5]

for i in range(5):
    m[31 - i] ^= m[31 - (i + 1) % 5]

# custom 31-round transformation
# ...


# -------------------------
# Stage 3
# -------------------------

# derived key
# modified delta
# 23-round transformation
# ...


# -------------------------
# Matrix stage
# -------------------------

mat = [
    [52, 12, 54, 39, 5, 28, 14],
    [2, 23, 60, 27, 38, 6, 62],
    [12, 52, 2, 14, 8, 27, 47],
    [7, 34, 29, 48, 6, 4, 40],
]

out = [0] * 4

for i in range(7):
    for j in range(4):
        out[j] += mat[j][i] * m[5 + i]

# final matrix constraints
# ...
```

The complete recovered constraint set is represented in the source analysis as a Python-equivalent checker.

---

# 20. Solver Approach

Once the checker is lifted to Python, solving it as a raw VM problem is unnecessary.

The preferred workflow is:

```text
BrainfOok
   ↓
semantic lifting
   ↓
Python constraint model
   ↓
SMT / symbolic solver
   ↓
candidate
   ↓
original VM verification
```

For the easy constraints, brute force over printable ASCII is enough.

For example:

```python
PRINTABLE = range(32, 127)

candidates = [
    c for c in PRINTABLE
    if c % 7 == 4
    and c % 11 == 7
    and c % 13 == 4
]
```

For the cryptographic portions, the cleanest approach is to encode the recovered Python arithmetic directly into an SMT solver.

Conceptually:

```python
from z3 import *

m = [Int(f"m{i}") for i in range(32)]

for c in m:
    solver.add(c >= 32)
    solver.add(c <= 126)

for i in range(31):
    solver.add(m[i] != m[i + 1])
```

Then add each recovered constraint.

For the first TEA-like stage:

```python
x = m[0] + (m[1] << 8)
y = m[2] + (m[3] << 8)

s = 0

for _ in range(17):
    s = s + delta

    y = (
        y
        + (
            ((x << 3) + k0)
            ^ (x + s)
            ^ ((x >> 2) + k1)
        )
    ) & 0xffff

    x = (
        x
        + (
            ((y << 1) + k2)
            ^ (y + s)
            ^ ((y >> 4) + k3)
        )
    ) & 0xffff
```

The exact solver implementation needs to preserve the original integer semantics, especially:

```text
// 
%
^
&
|
~
&
0xffff
```

and must not accidentally replace Python's arithmetic with C-style signed overflow.

---

# 21. Why This Is Better Than Full VM Emulation

A full VM emulator is useful during the initial reverse-engineering phase, but it is a poor final solving primitive.

Full emulation means the solver has to reason through:

```text
register pointer
memory pointer
instruction pointer
zero flag
jump stack
bit-memory stack
bit-memory bank
temporary values
```

for every instruction.

After semantic lifting, all of that collapses into:

```python
x = ...
y = ...
assert ...
```

The difference is enormous.

Instead of solving:

```text
thousands of instructions
```

we solve:

```text
~32 symbolic bytes
+ arithmetic constraints
+ three deterministic transformations
+ four linear equations
```

That is the abstraction level at which the challenge becomes tractable.

---

# 22. Verification

Even after obtaining a model satisfying the lifted constraints, the candidate should be executed against the original interpreter.

This catches subtle lifting errors involving:

* Python arbitrary-precision integers,
* negative values,
* integer division,
* bitwise NOT,
* implicit masking,
* memory-pointer state,
* dynamic jump offsets,
* and intentionally non-terminating branches.

The final validation should therefore be:

```python
candidate = bytes(...)

# First:
assert lifted_checker(candidate)

# Then:
run_original_brainfook(candidate)
```

Only the second test establishes that the recovered candidate is actually accepted by the challenge implementation.

---

# 23. Final Notes

The core reversing trick is **semantic compression**.

The original program is intentionally written at a very low abstraction level:

```text
BrainfOok instructions
        ↓
loops
        ↓
arithmetic primitives
        ↓
cryptographic operations
        ↓
constraints
```

Trying to solve at the first level is unnecessarily painful.

The useful progression is:

```text
1. Implement the VM.
2. Identify instruction semantics.
3. Identify recurring arithmetic idioms.
4. Trace dynamic jumps.
5. Remove only semantics-preserving obfuscation.
6. Split the payload into logical stages.
7. Lift loops into arithmetic.
8. Rewrite cryptographic blocks as Python.
9. Rewrite the final checker as constraints.
10. Solve the constraints.
11. Verify against the original VM.
```

The final flag is intentionally omitted.

The interesting part of this challenge is not the flag itself, but recovering the 32-byte input from a deliberately hostile execution environment.
