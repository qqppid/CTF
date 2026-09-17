# f, l and ag

## 1. Challenge Overview

`f, l and ag` is a cryptographic challenge from **DreamHack Invitational Quals**, authored by soon-haari. According to the author's write-up, the challenge ended with only one solve. It is described as a revenge version of the earlier `fl and ag` challenge.

The challenge initially looks like a standard RSA encryption problem:

* a 2048-bit RSA modulus is generated,
* the public exponent is fixed to \(e=257\),
* the flag is encrypted using textbook RSA,
* and only the public modulus, exponent, and ciphertexts are provided.

However, the actual vulnerability does not come from factoring the RSA modulus.

Instead, the challenge leaks a strong algebraic relationship between four plaintexts.

The 68-byte flag is divided into three pieces:

```text
             68-byte flag
    ┌────────────┬────────────┬──────────────────────┐
    │     f      │     l      │          ag          │
    │   17 bytes │   17 bytes │       34 bytes       │
    └────────────┴────────────┴──────────────────────┘
```

Each piece is encrypted independently, and then the entire concatenated flag is encrypted once more.

This gives four related RSA ciphertexts:

$$
f^e \bmod N
$$

$$
l^e \bmod N
$$

$$
ag^e \bmod N
$$

and

$$
flag^e \bmod N.
$$

The key observation is that the plaintexts are not independent.

The complete plaintext is exactly

$$
flag=f\|l\|ag.
$$

Once the byte concatenation is expressed as an integer equation, the four RSA ciphertexts form a multivariate polynomial system.

The attack can then be divided into three stages:

1. **Eliminate one variable from the multivariate polynomial system.**
2. **Use a Franklin–Reiter-style polynomial GCD attack to recover the normalized plaintext ratios.**
3. **Use LLL to reconstruct the original small plaintext chunks.**

The interesting part of the challenge is that these three techniques are chained together:

$$
\boxed{
\text{RSA relation}
\rightarrow
\text{Polynomial Elimination}
\rightarrow
\text{Franklin-Reiter}
\rightarrow
\text{LLL}
}
$$

---

# 2. Challenge Source

The challenge generation code is:

```python
from Crypto.Util.number import getPrime, GCD, bytes_to_long

while True:
    p = getPrime(1024)
    q = getPrime(1024)
    e = 0x101

    if GCD((p - 1) * (q - 1), e) == 1:
        break

N = p * q

with open('flag', 'rb') as f:
    flag = f.read()
    assert len(flag) == 68

f, l, ag = flag[:17], flag[17:34], flag[34:]

f, l, ag, flag = map(
    bytes_to_long,
    (f, l, ag, flag)
)

f_enc = pow(f, e, N)
l_enc = pow(l, e, N)
ag_enc = pow(ag, e, N)
flag_enc = pow(flag, e, N)
```

The public values are:

```python
print(f"{N = }")
print(f"{e = }")
print(f"{f_enc = }")
print(f"{l_enc = }")
print(f"{ag_enc = }")
print(f"{flag_enc = }")
```

The official challenge source confirms that the flag is exactly 68 bytes and that the split is:

```python
f   = flag[:17]
l   = flag[17:34]
ag  = flag[34:]
```

followed by independent RSA encryption of all four values.

---

# 3. RSA Model

Let us rename the plaintexts to make the mathematics easier to follow:

$$
A=f
$$

$$
B=l
$$

$$
C=ag
$$

$$
D=flag.
$$

Likewise, denote their ciphertexts by

$$
A_e=f_{enc}
$$

$$
B_e=l_{enc}
$$

$$
C_e=ag_{enc}
$$

$$
D_e=flag_{enc}.
$$

The public exponent is

$$
e=0x101=257.
$$

Therefore:

$$
A^{257}\equiv A_e\pmod N
$$

$$
B^{257}\equiv B_e\pmod N
$$

$$
C^{257}\equiv C_e\pmod N
$$

$$
D^{257}\equiv D_e\pmod N.
$$

All of the following calculations are performed in

$$
\mathbb Z_N.
$$

The important point is that we do **not** need the private exponent.

---

# 4. The Critical Structural Leak

The actual weakness is the concatenation:

$$
D=A\|B\|C.
$$

For an integer representation of a byte string, appending \(k\) bytes is equivalent to multiplying the previous integer by

$$
256^k.
$$

For example:

$$
A\|B
=
256^{17}A+B.
$$

Since \(C\) is 34 bytes long, \(B\) is followed by 34 bytes.

Likewise, \(A\) is followed by

$$
17+34=51
$$

bytes.

Therefore:

$$
\boxed{
D=256^{51}A+256^{34}B+C
}
$$

This equation is the central vulnerability in the challenge.

Without this relationship, the four RSA ciphertexts would essentially be independent RSA instances.

With it, they become algebraically related plaintexts.

---

# 5. Normalizing by \(C\)

The next step is to remove the absolute scale of the plaintexts.

Define

$$
a=\frac AC
$$

and

$$
b=\frac BC.
$$

These divisions are performed modulo \(N\), meaning that

$$
\frac AC
$$

is implemented as

$$
A C^{-1}\pmod N.
$$

Starting from

$$
D=256^{51}A+256^{34}B+C,
$$

divide by \(C\):

$$
\frac DC
=
256^{51}\frac AC
+
256^{34}\frac BC
+
1.
$$

Using the definitions of \(a\) and \(b\):

$$
\boxed{
\frac DC=256^{51}a+256^{34}b+1
}
$$

This is already much more useful.

---

# 6. Using RSA's Multiplicative Structure

RSA encryption is

$$
E(m)=m^e\bmod N.
$$

Therefore:

$$
\frac{D_e}{C_e}
=
\frac{D^e}{C^e}
=
\left(\frac DC\right)^e.
$$

Since \(e=257\):

$$
\frac{D_e}{C_e}
=
\left(
256^{51}a+
256^{34}b+
1
\right)^{257}.
$$

Thus we obtain:

$$
\boxed{
\left(
256^{51}a+
256^{34}b+
1
\right)^{257}
=
\frac{D_e}{C_e}
}
$$

We can also derive equations for \(a\) and \(b\) directly.

Because

$$
A^e=A_e
$$

and

$$
C^e=C_e,
$$

we have

$$
\frac{A_e}{C_e}
=
\frac{A^e}{C^e}
=
\left(\frac AC\right)^e
=
a^e.
$$

Therefore:

$$
\boxed{
a^{257}=\frac{A_e}{C_e}
}
$$

Similarly:

$$
\boxed{
b^{257}=\frac{B_e}{C_e}
}
$$

Now the RSA problem has been transformed into a polynomial problem.

---

# 7. Constructing the Polynomial System

Introduce formal variables \(x\) and \(y\), corresponding to \(a\) and \(b\).

Define:

$$
f_1(x,y)
=
(256^{51}x+256^{34}y+1)^{257}
-
\frac{D_e}{C_e}
$$

$$
f_2(x)
=
x^{257}
-
\frac{A_e}{C_e}
$$

and

$$
f_3(y)
=
y^{257}
-
\frac{B_e}{C_e}.
$$

The actual solution satisfies:

$$
f_1(a,b)=0
$$

$$
f_2(a)=0
$$

$$
f_3(b)=0.
$$

So we have the following system:

$$
\boxed{
\begin{cases}
f_1(a,b)=0\\
f_2(a)=0\\
f_3(b)=0
\end{cases}
}
$$

At this point, the problem is no longer primarily about RSA.

It is an algebraic elimination problem over \(\mathbb Z_N\).

---

# 8. Why Standard Franklin–Reiter Is Not Immediately Applicable

Franklin–Reiter related-message attacks are normally applied when two polynomial equations share one unknown root.

For example:

$$
f(x)=0
$$

and

$$
g(x)=0
$$

where both contain the same unknown \(x\).

Computing their polynomial GCD reveals the common factor corresponding to the unknown plaintext.

Here, however, the first polynomial is

$$
f_1(x,y)
$$

and contains two variables.

We cannot simply calculate

$$
\gcd(f_1,f_2)
$$

as ordinary univariate polynomials because \(y\) is still present.

A natural solution would be to use a multivariate Gröbner basis.

That approach is theoretically valid, but it is unnecessarily heavy for this challenge.

The intended approach is much simpler:

> Temporarily treat \(y\) as belonging to the coefficient ring and eliminate \(x\).

The official write-up describes exactly this approach.

---

# 9. Nested Polynomial Rings in SageMath

SageMath allows us to construct a polynomial ring whose coefficients are themselves polynomials.

First:

```python
Q.<y> = PolynomialRing(Zmod(N))
```

This means:

$$
Q=\mathbb Z_N[y].
$$

Then:

```python
P.<x> = PolynomialRing(Q)
```

which gives:

$$
P=Q[x]
=
\mathbb Z_N[y][x].
$$

From the perspective of \(P\):

* \(x\) is the polynomial variable,
* \(y\) belongs to the coefficient ring.

This lets us treat the two-variable polynomial as a univariate polynomial in \(x\).

The corresponding SageMath construction is:

```python
Q.<y> = PolynomialRing(Zmod(N))
P.<x> = PolynomialRing(Q)

f1 = P(
    (x * 256^51 + y * 256^34 + 1)^e
    - (flag_enc / ag_enc) % N
)

f2 = P(
    x^e
    - (f_enc / ag_enc) % N
)

f3 = Q(
    y^e
    - (l_enc / ag_enc) % N
)
```

The official solver uses the same nested-ring construction.

---

# 10. The Elimination Objective

We know that the correct values \(a,b\) satisfy:

$$
f_1(a,b)=0
$$

and

$$
f_2(a)=0.
$$

We want to eliminate \(x\).

Conceptually, this is similar to the Euclidean algorithm for polynomials.

Suppose:

$$
f_1(x)=c_1x^d+\cdots
$$

and

$$
f_2(x)=c_2x^k+\cdots.
$$

Normally, we would divide by \(c_2\) to cancel the highest-order term.

For example:

$$
f_1
-
\frac{c_1}{c_2}x^{d-k}f_2.
$$

But there is a problem.

The coefficients \(c_1,c_2\) are polynomials in \(y\).

We cannot necessarily invert them in

$$
\mathbb Z_N[y].
$$

In particular, a nonzero polynomial in \(y\) is not generally a unit.

Therefore, ordinary monic polynomial division is not available in the required form.

---

# 11. Denominator-Free Leading-Term Cancellation

The workaround is straightforward.

Instead of calculating

$$
f_1-\frac{c_1}{c_2}x^{d-k}f_2,
$$

multiply the first polynomial by \(c_2\) and the second by \(c_1\):

$$
c_2f_1
-
c_1x^{d-k}f_2.
$$

Now the highest-degree terms cancel:

$$
c_2c_1x^d
-
c_1c_2x^d
=0.
$$

This decreases the degree in \(x\) without requiring the inverse of \(c_2\).

This is essentially a denominator-free version of the Euclidean polynomial reduction.

The implementation is:

```python
f1_coef = f1[f1.degree()]
f2_coef = f2[f2.degree()]

f1 *= f2_coef
f2 *= f1_coef

f1 -= f2 * x^(f1.degree() - f2.degree())
```

This is one of the most important implementation details in the solve.

---

# 12. Why We Also Reduce Modulo \(f_3\)

There is a second problem.

The coefficients of \(f_1\) and \(f_2\) are polynomials in \(y\).

Repeated multiplication causes these coefficients to grow extremely quickly.

However, we already know:

$$
f_3(b)=0.
$$

Therefore, whenever a coefficient polynomial \(h(y)\) is replaced by

$$
h(y)\bmod f_3(y),
$$

its value at \(y=b\) remains unchanged.

That is:

$$
h(b)
=
(h\bmod f_3)(b).
$$

Consequently, we can safely reduce every coefficient modulo \(f_3\).

This keeps the degree in \(y\) below 257.

In SageMath:

```python
f1 = P([coef % f3 for coef in list(f1)])
f2 = P([coef % f3 for coef in list(f2)])
```

This operation is not merely an optimization.

It is what makes the elimination computationally practical.

---

# 13. Complete Elimination Loop

The elimination can therefore be implemented as:

```python
while f2.degree() > 0:
    f1_coef = f1[f1.degree()]
    f2_coef = f2[f2.degree()]

    f1 *= f2_coef
    f2 *= f1_coef

    f1 = P([
        coef % f3
        for coef in list(f1)
    ])

    f2 = P([
        coef % f3
        for coef in list(f2)
    ])

    f1 -= f2 * x^(f1.degree() - f2.degree())

    if f1.degree() < f2.degree():
        f1, f2 = f2, f1

g = f2[0]
```

The official solver performs this process for 513 iterations, corresponding to the degree reduction process required by the two degree-257 polynomials.

At the end:

```python
g = f2[0]
```

is a polynomial only in \(y\).

Therefore:

$$
\boxed{g(b)=0}
$$

---

# 14. What We Have Achieved

Originally:

$$
f_1(x,y)
$$

contained two unknowns.

After elimination:

$$
g(y)
$$

contains only one.

The problem has therefore been transformed from:

$$
(a,b)
$$

to:

$$
b.
$$

This is the critical reduction.

We can now return to a normal univariate polynomial GCD attack.

---

# 15. Recovering \(b\)

We now have two polynomials sharing the root \(b\):

$$
g(b)=0
$$

and

$$
f_3(b)=0.
$$

Therefore:

$$
\gcd(g,f_3)
$$

must contain the factor

$$
y-b.
$$

We can compute the polynomial Euclidean algorithm:

```python
g1 = g
g2 = f3

while g2.degree() > 0:
    g1 = g1 % g2
    g1, g2 = g2, g1
```

The solver verifies:

```python
assert g1.degree() == 1
```

Therefore:

$$
g_1(y)=k(y-b)
$$

for some nonzero constant \(k\).

After making it monic:

```python
b = ZZ(-g1.monic()[0])
```

we recover:

$$
\boxed{b=B/C}.
$$

This is the Franklin–Reiter stage of the attack.

The official solve script follows exactly this process.

---

# 16. Recovering \(a\)

Now \(b\) is known.

We can substitute it into the original two-variable equation:

$$
f_1(x,b)
=
(256^{51}x+256^{34}b+1)^{257}
-
\frac{D_e}{C_e}.
$$

The equation

$$
f_2(x)
=
x^{257}
-
\frac{A_e}{C_e}
$$

also holds for \(x=a\).

At this point both polynomials are univariate in \(x\):

$$
f_1(x,b)
$$

and

$$
f_2(x).
$$

So we can once again apply the Euclidean algorithm.

In SageMath:

```python
P.<x> = PolynomialRing(Zmod(N))

f1 = P(
    (x * 256^51 + b * 256^34 + 1)^e
    - (flag_enc / ag_enc) % N
)

f2 = P(
    x^e
    - (f_enc / ag_enc) % N
)

while f2.degree() > 0:
    f1 = f1 % f2
    f1, f2 = f2, f1

assert f1.degree() == 1

a = ZZ(-f1.monic()[0])
```

Thus:

$$
\boxed{a=A/C}
$$

is recovered.

At this point, the RSA-related algebraic portion of the attack is finished.

---

# 17. Why We Still Cannot Directly Recover the Flag

We now know:

$$
a=\frac AC
$$

and

$$
b=\frac BC.
$$

It may initially look like this is enough.

It is not.

The values \(a\) and \(b\) are ratios modulo \(N\).

We still need the actual integers:

$$
A,\ B,\ C.
$$

In particular, we need \(C\) so that:

$$
A=aC\bmod N
$$

and

$$
B=bC\bmod N.
$$

The next question is therefore:

> Given \(a=A/C\bmod N\), how can we recover the small integers \(A\) and \(C\)?

This is where the plaintext size becomes important.

---

# 18. Size Bounds

The RSA modulus is approximately 2048 bits:

$$
N\approx2^{2048}.
$$

However:

$$
A<2^{8\cdot17}=2^{136}
$$

and

$$
B<2^{136}.
$$

For \(C\):

$$
C<2^{8\cdot34}=2^{272}.
$$

So we have:

```text
N : approximately 2048 bits
A : at most 136 bits
B : at most 136 bits
C : at most 272 bits
```

This is an enormous size gap.

The relation

$$
a=\frac AC\pmod N
$$

can be rewritten as

$$
A\equiv aC\pmod N.
$$

Therefore:

$$
A-aC\equiv0\pmod N.
$$

There exists some integer \(k\) such that

$$
A-aC=kN.
$$

The important fact is that \(A\) and \(C\) are tiny relative to \(N\).

This turns the problem into a small-vector/lattice problem.

---

# 19. Lattice Construction

We want a lattice containing vectors corresponding to

$$
(A,C).
$$

A simple basis is:

$$
M=
\begin{pmatrix}
1&a\\
0&N
\end{pmatrix}.
$$

The official solve script constructs exactly this matrix:

```python
M = Matrix([
    [1, a],
    [0, N]
])
```

and then applies:

```python
M.LLL()
```

The official implementation is:

```python
M = Matrix([[1, a], [0, N]])
ag_base = ZZ(M.LLL()[0][0])
ag_base = abs(ag_base)
```

---

# 20. Why This Lattice Contains the Desired Relation

Consider a row vector

$$
(x,y).
$$

Multiplying by the matrix gives:

$$
(x,y)
\begin{pmatrix}
1&a\\
0&N
\end{pmatrix}
=
(x,\ ax+yN).
$$

For the correct \(C\), if

$$
A\equiv aC\pmod N,
$$

then there exists an integer \(k\) such that:

$$
A-aC=kN.
$$

Equivalently:

$$
aC-kN=A.
$$

Thus a vector of the form

$$
(C,-k)
$$

maps to a lattice vector containing the small value \(A\):

$$
(C,-k)
\begin{pmatrix}
1&a\\
0&N
\end{pmatrix}
=
(C,aC-kN).
$$

Depending on sign convention, this becomes:

$$
(C,A)
$$

or an equivalent signed representation.

The exact row orientation is not important because LLL is insensitive to sign and basis ordering for this purpose.

The essential point is:

$$
\boxed{
(C,A)
\text{ is represented by a very short lattice vector.}
}
$$

Since \(A\) and \(C\) are dramatically smaller than \(N\), LLL can identify this short vector.

---

# 21. Recovering \(C\)

The solver obtains a candidate base value:

```python
ag_base = ZZ(M.LLL()[0][0])
ag_base = abs(ag_base)
```

This gives a value related to the small plaintext \(C\).

The implementation then tests multiples:

```python
ag = ag_base

while True:
    try:
        long_to_bytes(ag).decode()
        break
    except:
        ag += ag_base
```

The reason for checking multiples is that the lattice relation may recover a primitive/base vector rather than immediately returning the exact 34-byte plaintext integer.

Because the expected plaintext is a byte string, converting candidate values back to bytes gives a practical validation condition.

Eventually the correct:

$$
\boxed{C=ag}
$$

is obtained.

---

# 22. Recovering \(A\) and \(B\)

Once \(C\) is known:

$$
A\equiv aC\pmod N
$$

and

$$
B\equiv bC\pmod N.
$$

Therefore:

```python
f = a * ag % N
l = b * ag % N
```

The official solver performs exactly this reconstruction.

Because \(A\) and \(B\) are only 17 bytes long, their resulting representatives correspond to the original chunks.

---

# 23. Reconstructing the Original Flag

We now have:

```text
A = f
B = l
C = ag
```

with sizes:

```text
A : 17 bytes
B : 17 bytes
C : 34 bytes
```

The flag can therefore be reconstructed as:

```python
flag = (
    int(f).to_bytes(17, "big")
    + int(l).to_bytes(17, "big")
    + int(ag).to_bytes(34, "big")
)

print(flag.decode())
```

This is the final line of the official solver.

---

# 24. Full Solve Script

Putting the entire attack together gives:

```python
from Crypto.Util.number import *
from tqdm import trange

exec(open("output.txt", "r").read())

N, e, f_enc, l_enc, ag_enc, flag_enc = map(
    ZZ,
    (N, e, f_enc, l_enc, ag_enc, flag_enc)
)

# ============================================================
# Step 1: Construct the polynomial system
# ============================================================

Q.<y> = PolynomialRing(Zmod(N))
P.<x> = PolynomialRing(Q)

f1 = P(
    (x * 256^51 + y * 256^34 + 1)^e
    - (flag_enc / ag_enc) % N
)

f2 = P(
    x^e
    - (f_enc / ag_enc) % N
)

f3 = Q(
    y^e
    - (l_enc / ag_enc) % N
)

# ============================================================
# Eliminate x
# ============================================================

for _ in trange(513):

    f1_coef = f1[f1.degree()]
    f2_coef = f2[f2.degree()]

    # Denominator-free leading-term cancellation
    f1 *= f2_coef
    f2 *= f1_coef

    # Keep coefficients small by reducing modulo f3
    f1 = P([
        coef % f3
        for coef in list(f1)
    ])

    f2 = P([
        coef % f3
        for coef in list(f2)
    ])

    # Cancel the highest x-degree term
    f1 -= f2 * x^(f1.degree() - f2.degree())

    if f1.degree() < f2.degree():
        f1, f2 = f2, f1

g = f2[0]

# ============================================================
# Step 2: Recover b
# ============================================================

g1 = g
g2 = f3

while g2.degree() > 0:
    g1 = g1 % g2
    g1, g2 = g2, g1

assert g1.degree() == 1

b = ZZ(-g1.monic()[0])

# ============================================================
# Recover a
# ============================================================

P.<x> = PolynomialRing(Zmod(N))

f1 = P(
    (x * 256^51 + b * 256^34 + 1)^e
    - (flag_enc / ag_enc) % N
)

f2 = P(
    x^e
    - (f_enc / ag_enc) % N
)

while f2.degree() > 0:
    f1 = f1 % f2
    f1, f2 = f2, f1

assert f1.degree() == 1

a = ZZ(-f1.monic()[0])

# ============================================================
# Step 3: Recover C = ag using LLL
# ============================================================

M = Matrix([
    [1, a],
    [0, N]
])

ag_base = ZZ(M.LLL()[0][0])
ag_base = abs(ag_base)

ag = ag_base

while True:
    try:
        long_to_bytes(ag).decode()
        break
    except:
        ag += ag_base

# ============================================================
# Recover A and B
# ============================================================

f = a * ag % N
l = b * ag % N

# ============================================================
# Reconstruct flag
# ============================================================

flag = (
    int(f).to_bytes(17, "big")
    + int(l).to_bytes(17, "big")
    + int(ag).to_bytes(34, "big")
)

print(flag.decode())
```

The structure and critical operations above follow the author's publicly released solver.

---

# 25. A More Detailed Mathematical View

It is useful to summarize the attack entirely algebraically.

We start with:

$$
A^e=A_e
$$

$$
B^e=B_e
$$

$$
C^e=C_e
$$

$$
D^e=D_e.
$$

The concatenation gives:

$$
D=sA+tB+C
$$

where

$$
s=256^{51}
$$

and

$$
t=256^{34}.
$$

Define:

$$
a=A/C,\qquad b=B/C.
$$

Then:

$$
D/C=sa+tb+1.
$$

Raising both sides to \(e\):

$$
D_e/C_e=(sa+tb+1)^e.
$$

Meanwhile:

$$
A_e/C_e=a^e
$$

and

$$
B_e/C_e=b^e.
$$

Thus:

$$
\begin{cases}
(sa+tb+1)^e=D_e/C_e\\
a^e=A_e/C_e\\
b^e=B_e/C_e.
\end{cases}
$$

This is exactly the system:

$$
\begin{cases}
f_1(a,b)=0\\
f_2(a)=0\\
f_3(b)=0.
\end{cases}
$$

Eliminate \(a\):

$$
f_1,f_2
\longrightarrow
g(b).
$$

Then:

$$
\gcd(g,f_3)
\longrightarrow
b.
$$

Then:

$$
\gcd(f_1(x,b),f_2(x))
\longrightarrow
a.
$$

Finally:

$$
a=A/C
$$

with small \(A,C\), allowing lattice recovery.

---

# 26. Why the Public Exponent Matters

The challenge uses:

$$
e=257.
$$

This is not itself sufficient to break RSA.

A 257-bit? No — \(257\) is simply a small integer exponent.

The security issue comes from the interaction between:

* repeated encryption with the same modulus,
* deterministic textbook RSA,
* algebraically related plaintexts,
* and the known concatenation structure.

The exponent being relatively small makes the resulting polynomial degree manageable:

$$
\deg(f_1)=\deg(f_2)=\deg(f_3)=257.
$$

A much larger exponent would make the polynomial elimination significantly more expensive.

Therefore, the weakness should not be summarized as simply:

> "RSA with \(e=257\) is broken."

That would be inaccurate.

The actual weakness is:

> **Textbook RSA is being applied to several strongly related plaintexts, and the relationship is sufficiently structured to construct a low-dimensional polynomial system.**

---

# 27. Why Factoring \(N\) Is Unnecessary

A common first approach to an RSA challenge is:

```text
Can N be factored?
```

Here the answer is expected to be no.

The challenge generates:

```python
p = getPrime(1024)
q = getPrime(1024)

N = p * q
```

so \(N\) is a conventional approximately 2048-bit RSA modulus.

The attack never attempts to calculate:

$$
\varphi(N)
$$

or

$$
d=e^{-1}\pmod{\varphi(N)}.
$$

Instead, it works entirely with publicly available quantities:

$$
N,e,A_e,B_e,C_e,D_e.
$$

This is a good example of an important cryptanalytic principle:

> A cryptosystem can remain difficult to invert in isolation while becoming vulnerable when the same primitive is repeatedly applied to related messages.

---

# 28. Why Textbook RSA Is the Problem

The encryption function used by the challenge is:

$$
c=m^e\bmod N.
$$

There is no randomized padding.

Modern RSA encryption normally uses a randomized padding scheme such as RSA-OAEP.

With textbook RSA:

$$
E(m)=m^e\bmod N
$$

is deterministic and algebraically transparent.

For example:

$$
\frac{E(m_1)}{E(m_2)}
=
\left(\frac{m_1}{m_2}\right)^e
\pmod N.
$$

This exact property is exploited by the challenge.

The ratios

$$
A/C
$$

and

$$
B/C
$$

survive RSA encryption in the sense that:

$$
A_e/C_e=(A/C)^e
$$

and

$$
B_e/C_e=(B/C)^e.
$$

The challenge therefore unintentionally exposes enough algebraic structure to solve for these ratios.

---

# 29. Why the Byte Lengths Matter

The split:

```text
17 bytes
17 bytes
34 bytes
```

is not merely cosmetic.

It creates the exact integer relation:

$$
D=256^{51}A+256^{34}B+C.
$$

It also gives strong size bounds:

$$
A,B<2^{136}
$$

and

$$
C<2^{272}.
$$

These bounds are what make the final LLL step possible.

If the plaintext chunks were all approximately as large as the RSA modulus, the small-vector assumption would disappear and the lattice attack would no longer be directly applicable.

Thus the challenge combines two kinds of leakage:

1. **Algebraic leakage** from concatenation.
2. **Size leakage** from the known plaintext lengths.

Both are required for the complete attack.

---

# 30. Why LLL Works in Only Two Dimensions

A particularly elegant part of the challenge is the final lattice.

We do not need a complicated high-dimensional Coppersmith lattice.

Once \(a=A/C\) has been recovered, the only relation we need is:

$$
A\equiv aC\pmod N.
$$

This is a two-variable modular relation.

Therefore a 2-dimensional lattice is sufficient:

$$
M=
\begin{pmatrix}
1&a\\
0&N
\end{pmatrix}.
$$

LLL reduces this basis to a short-vector basis.

Because the target values are only:

$$
|A|<2^{136}
$$

and

$$
|C|<2^{272},
$$

while:

$$
N\approx2^{2048},
$$

the desired relation is exceptionally small compared with the modulus.

This is why the final reconstruction is surprisingly compact in code:

```python
M = Matrix([[1, a], [0, N]])
M.LLL()
```

The official solver uses precisely this construction.

---

# 31. Attack Dependency Graph

The solve can be visualized as a dependency graph:

```text
                    RSA ciphertexts
                          │
                          ▼
              ┌──────────────────────┐
              │ Concatenation relation│
              │ D = 256^51 A +       │
              │     256^34 B + C     │
              └──────────┬───────────┘
                         │
                         ▼
                Normalize by C
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
           a = A/C               b = B/C
              │                     │
              └──────────┬──────────┘
                         ▼
                 Polynomial System
                         │
                         ▼
                 Eliminate x / a
                         │
                         ▼
                       g(y)
                         │
                         ▼
              gcd(g, f3) → b
                         │
                         ▼
              gcd(f1(x,b),f2)
                         │
                         ▼
                       a
                         │
                         ▼
                  a = A/C mod N
                         │
                         ▼
                  2D Lattice
                         │
                         ▼
                        LLL
                         │
                         ▼
                        C
                         │
                  ┌──────┴──────┐
                  ▼             ▼
              A = aC        B = bC
                  │             │
                  └──────┬──────┘
                         ▼
                       A || B || C
                         │
                         ▼
                        FLAG
```

---

# 32. Important Implementation Details

There are several details that are easy to overlook when implementing this attack from scratch.

### 32.1 Use the correct coefficient ring

The construction must distinguish between:

```python
Zmod(N)
```

and

```python
PolynomialRing(Zmod(N))
```

and the nested ring:

```python
PolynomialRing(Q)
```

The intended structure is:

$$
\mathbb Z_N[y][x].
$$

---

### 32.2 Polynomial division is not ordinary integer division

Expressions such as:

```python
flag_enc / ag_enc
```

inside `Zmod(N)` mean modular division:

$$
flag_{enc}\cdot ag_{enc}^{-1}\pmod N.
$$

This is valid as long as the denominator is invertible modulo \(N\).

---

### 32.3 Preserve the modulus

The polynomial equations are not over the integers.

They are equations over:

$$
\mathbb Z_N.
$$

Therefore, converting coefficients into ordinary Python integers too early can break the algebra.

---

### 32.4 Reduce coefficients modulo \(f_3\)

Without:

```python
coef % f3
```

the coefficient polynomials in \(y\) grow rapidly.

The reduction is mathematically valid because:

$$
f_3(b)=0.
$$

---

### 32.5 Do not make the polynomial monic during the first elimination

This is one of the most subtle points.

The leading coefficient is a polynomial in \(y\), not necessarily a unit.

Therefore:

```text
divide by leading coefficient
```

is not generally valid.

Instead:

```text
multiply by the other leading coefficient
→ subtract
→ cancel highest term
```

must be used.

---

# 33. A Cleaner Conceptual Interpretation

The attack can be understood as finding a hidden common root.

Initially:

$$
a,b
$$

are unknown.

The three equations describe a common point:

$$
(a,b).
$$

The first equation gives a curve:

$$
f_1(x,y)=0.
$$

The second gives another curve:

$$
f_2(x)=0.
$$

The third gives:

$$
f_3(y)=0.
$$

The elimination procedure computes an algebraic consequence of the first two equations that no longer contains \(x\):

$$
g(y)=0.
$$

Therefore the original two-dimensional intersection is projected onto the \(y\)-axis.

The common root is then recovered through:

$$
\gcd(g,f_3).
$$

After \(b\) is known, the system collapses back to one dimension, making \(a\) recoverable through another polynomial GCD.

This is essentially a hand-crafted elimination strategy specialized to the structure of the challenge.

---

# 34. Comparison with a Gröbner Basis Approach

A generic mathematical solution would be to compute a Gröbner basis of:

$$
\langle f_1,f_2,f_3\rangle.
$$

With an appropriate variable ordering, elimination theory could produce a polynomial containing only \(y\).

Conceptually:

$$
\{f_1,f_2,f_3\}
$$

would be transformed into something like:

$$
\{g(y),\ldots\}.
$$

However, this challenge does not require such a heavyweight approach.

The nested-ring method effectively performs the required elimination manually:

```text
treat y as coefficient
        ↓
Euclidean-style reduction in x
        ↓
reduce coefficients modulo f3
        ↓
x disappears
        ↓
obtain g(y)
```

This is significantly more specialized, but also significantly more efficient for the exact structure of this challenge.

---

# 35. Security Lessons

This challenge demonstrates several practical lessons about RSA.

## 35.1 Never use textbook RSA for encryption

Raw RSA:

$$
c=m^e\bmod N
$$

is deterministic and algebraically malleable.

Encryption should use a randomized padding scheme such as RSA-OAEP.

---

## 35.2 Related plaintexts are dangerous

Even if each individual plaintext is sufficiently large, exposing algebraic relationships between plaintexts can invalidate the security assumptions of the primitive.

---

## 35.3 Concatenation can create algebraic relations

The operation:

```text
A || B || C
```

looks like a string operation.

After converting the string to an integer, however, it becomes:

$$
256^{51}A+256^{34}B+C.
$$

That is a polynomial relation.

Cryptographic analysis must therefore consider how serialization affects the mathematical representation of data.

---

## 35.4 Known message lengths can be cryptographically significant

Knowing that a value is exactly 17 or 34 bytes gives strong numerical bounds.

Those bounds can turn a modular equation into a lattice problem.

---

# 36. Final Takeaway

The challenge is not solved by breaking RSA itself.

Instead, it exploits the fact that the implementation exposes too much structure around RSA.

The complete chain is:

$$
\boxed{
D=A\|B\|C
}
$$

which becomes:

$$
\boxed{
D=256^{51}A+256^{34}B+C
}
$$

Normalize by \(C\):

$$
\boxed{
a=A/C,\qquad b=B/C
}
$$

and derive:

$$
\boxed{
(256^{51}a+256^{34}b+1)^{257}=D_e/C_e
}
$$

$$
\boxed{
a^{257}=A_e/C_e
}
$$

$$
\boxed{
b^{257}=B_e/C_e
}
$$

Then:

$$
\boxed{
\text{eliminate }a
\rightarrow
g(b)
}
$$

followed by:

$$
\boxed{
\gcd(g,f_3)
\rightarrow
b
}
$$

then:

$$
\boxed{
\gcd(f_1(x,b),f_2)
\rightarrow
a
}
$$

and finally:

$$
\boxed{
a=A/C
\rightarrow
\text{LLL}
\rightarrow
C
}
$$

after which:

$$
A=aC\bmod N
$$

$$
B=bC\bmod N.
$$

Finally:

$$
\boxed{
flag=A\|B\|C
}
$$

The challenge is particularly valuable from a cryptography-learning perspective because it combines several techniques that are often studied independently:

* textbook RSA algebra,
* related-message attacks,
* Franklin–Reiter,
* polynomial GCD,
* polynomial elimination,
* nested polynomial rings,
* modular polynomial arithmetic,
* lattice construction,
* LLL reduction,
* and small plaintext reconstruction.

The key lesson is that the RSA modulus itself was never the weak point. The weakness was the **relationship between the messages encrypted under the same RSA key**. The public solver demonstrates that once that relationship is translated into algebra, the apparently hard RSA inversion problem collapses into a sequence of tractable algebraic and lattice problems.
