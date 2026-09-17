# Innumerable

## Introduction

This challenge looked quite annoying at first because most of the interesting logic was hidden behind a large amount of rule-processing code.

Instead of completely reversing the binary, I decided to attack the problem from the data side.

The basic idea was:

1. Find how the `rules` object is represented.
2. Dump the entire rule table from memory.
3. Reconstruct it into a Python dictionary.
4. Understand the semantics of the nested rule structure.
5. Reduce every rule to the set of hexadecimal characters it can match.
6. Analyze `filter`.
7. Recover the 64-byte flag from the resulting constraints.

This approach worked surprisingly well because the binary contains a lot of complicated-looking logic, but the actual rule data has a much simpler structure.

---

# 1. Finding the Rule Structure

The first useful thing I found while reversing was the structure of the hash table.

The rule table is essentially a hash table mapping a string key to a node. Each node contains a nested vector structure representing the rule, together with some strings used for the result message.

The relevant structures recovered in IDA were approximately:

```c
struct block
{
    std_string name;
    unsigned __int8 num;
};

struct vector_block
{
    block *start;
    block *end;
    block *capacity;
};

struct vector_vector_block
{
    vector_block *start;
    vector_block *end;
    vector_block *capacity;
};

struct node
{
    vector_vector_block container;
    std_string msg;
    std_string n1;
};

struct key_block_line
{
    std_string key;
    node val;
};

struct _Hash_node
{
    _Hash_node *_M_next;
    key_block_line obj;
    size_t _M_hash_code;
};
```

The important observation here is that a rule is not stored as one flat structure.

It is essentially:

```text
rule
 └── vector<vector<block>>
```

and each `block` has:

```text
name
num
```

The `name` identifies another rule, while `num` determines how that block should be interpreted.

---

# 2. Dumping the Hashtable

Fully reversing all of the code manipulating these structures would take quite a bit of time.

Since the complete rule table already existed in memory, I decided to dump it directly using GDB's Python API.

The first thing needed was a few helpers for reading primitive types and `std::string` objects:

```python
import gdb
import struct


def read1(addr):
    return struct.unpack("<B", read_bytes(addr, 1))[0]


def read8(addr):
    return struct.unpack("<Q", read_bytes(addr, 8))[0]


def read_bytes(addr, length):
    mem = gdb.selected_inferior().read_memory(addr, length)
    return mem.tobytes()


def read_str(addr):
    literal_addr = read8(addr)

    if literal_addr == 0:
        return ''

    try:
        str_len = read8(addr + 8)
        s = read_bytes(literal_addr, str_len)
        return s.decode(errors='ignore')
    except:
        return ''
```

The `block` structure can then be recovered using the offsets found in IDA:

```python
def read_block(addr):
    n_str = read_str(addr)
    n_num = read1(addr + 0x20)

    if n_num not in [0, 1]:
        print(f'invalid at {hex(addr + 0x20)}')

    return (n_str, n_num)
```

The `std::vector` layout is particularly convenient because it consists of `start`, `end`, and `capacity`.

Therefore, the number of elements is simply:

```text
(end - start) / sizeof(element)
```

For a vector of blocks, the block size was `0x28`:

```python
def read_vector_line(addr):
    st = read8(addr)
    ed = read8(addr + 8)

    assert st <= ed, f'{st} -> {ed} not suitable'

    return [
        read_block(st + i * 0x28)
        for i in range((ed - st) // 0x28)
    ]
```

And the outer vector contains vectors whose size is `0x18`:

```python
def read_vector_vector_line(addr):
    st = read8(addr)
    ed = read8(addr + 8)

    assert st <= ed, f'{st} -> {ed} not suitable'

    return [
        read_vector_line(st + i * 0x18)
        for i in range((ed - st) // 0x18)
    ]
```

Finally, the complete hash node can be reconstructed:

```python
def read_block_line(addr):
    vv = read_vector_vector_line(addr)

    key = read_str(addr + 0x18 + 0x20)

    return (vv, key)


def read_hash_node(addr):
    next_addr = read8(addr)

    key = read_str(addr + 8)

    block_line = read_block_line(addr + 8 + 0x20)[0]

    return (next_addr, key, block_line)
```

The hash table uses chained buckets, so I followed `_M_next` until reaching zero:

```python
def build_hash_line(addr):
    if addr == 0:
        return {}

    N = addr
    outp = {}

    while N:
        ad, key, val = read_hash_node(N)

        outp[key] = val

        N = ad

    return outp
```

Then I iterated over every bucket:

```python
def build_hashtable(addr):
    visited = set()
    big_dict = {}

    table_addr = read8(addr)
    amount = read8(addr + 8)

    print(
        f"[+] Table at {hex(table_addr)} "
        f"with {amount} buckets"
    )

    for i in range(amount):
        hash_line_addr = table_addr + 8 * i
        bucket_ptr = read8(hash_line_addr)

        if bucket_ptr != 0:
            if bucket_ptr in visited:
                print("LOOP detected")
                break

            visited.add(bucket_ptr)

            h = build_hash_line(bucket_ptr)

            for k in h:
                if k in big_dict:
                    if big_dict[k] != h[k]:
                        print(
                            f"[ERROR] Duplicate key "
                            f"with conflicting values: {k}"
                        )
                        sys.exit(1)
                else:
                    big_dict[k] = h[k]

        print(len(big_dict))

    dump_dict(big_dict, './dump/total.txt')
```

The table itself was located from the stack/rules object in GDB, and the script was then run against the hashtable address. The original dump script and its offsets are documented in the source material.

This took roughly 20 minutes on my machine.

Eventually, I had a text dump containing entries such as:

```text
[key] pat_2c274f44: [
   [('pat_6fbefa9b', 0), ('pat_b245a7d0', 0)],
]

[key] pat_877267c0: [
   [('any', 1), ('7', 1), ('any', 1)],
   [('any', 1), ('a', 1), ('any', 1)],
   [('any', 1), ('5', 1), ('any', 1)],
   [('any', 1), ('e', 1), ('any', 1)],
]
```

At this point, the challenge was no longer a pure reversing problem.

It had become a rule-solving problem.

---

# 3. Understanding the Rule Format

The important thing is how the nested vectors are interpreted.

Conceptually, each rule looks like:

```text
RULE
 ├── LIST
 │    ├── VALUE
 │    ├── VALUE
 │    └── ...
 ├── LIST
 │    ├── VALUE
 │    └── ...
 └── ...
```

The semantics are:

```text
RULE = LIST1 OR LIST2 OR ...
LIST = VALUE1 AND VALUE2 AND ...
```

Therefore, a rule is an **OR of AND clauses**.

For example:

```text
[
    [A, B],
    [C, D],
    [E]
]
```

means:

```text
(A AND B) OR
(C AND D) OR
(E)
```

This is the most important observation for solving the challenge.

The source analysis reached the same conclusion from the checker: a line requires all nodes inside it to be correct, while a rule requires at least one line to be correct.

---

# 4. The `any` Rule

One particularly useful rule was:

```python
rules[b'any']
```

which evaluates to:

```text
[
    [b'0'],
    [b'1'],
    [b'2'],
    [b'3'],
    [b'4'],
    [b'5'],
    [b'6'],
    [b'7'],
    [b'8'],
    [b'9'],
    [b'a'],
    [b'b'],
    [b'c'],
    [b'd'],
    [b'e'],
    [b'f']
]
```

So `any` simply represents every possible hexadecimal character:

```python
ANY = set(b'0123456789abcdef')
```

This tells us that the actual input consists of hexadecimal characters.

Since the final flag string inside `DH{...}` is 64 characters long, the natural assumption is that we are looking for a 64-character hexadecimal string.

---

# 5. Reducing Rules to Character Sets

Instead of evaluating the entire recursive rule graph every time, I decided to reduce every rule to a set of possible characters.

For a leaf node:

```python
b'7'
```

the result is simply:

```python
{'7'}
```

For `any`:

```python
ANY
```

For a rule, the inner values of a line are ANDed, so their possible sets must be intersected.

Different lines are ORed, so their resulting sets are unioned.

That gives:

```python
def get_set(k):
    # Literal character
    if len(k) == 1:
        return {k}

    # Any hexadecimal character
    if k == b'any':
        return set(ANY)

    ks = rules[k]

    result = set()

    # OR between lines
    for line in ks:

        # AND inside a line
        line_set = set(ANY)

        for child in line:
            child_set = get_set(child)

            line_set = line_set.intersection(child_set)

        result = result.union(line_set)

    return result
```

So mathematically, if a rule is:

```text
R = L1 OR L2 OR ... OR Ln
```

then:

```text
S(R) = S(L1) ∪ S(L2) ∪ ... ∪ S(Ln)
```

and for a line:

```text
L = A AND B AND ... AND C
```

we have:

```text
S(L) = S(A) ∩ S(B) ∩ ... ∩ S(C)
```

This turns a complicated recursive boolean expression into a very small set of hexadecimal characters.

---

# 6. Understanding `line`, `filter`, and `correct`

The top-level rules were particularly useful.

The messages were:

```python
ss = {
    b'correct': b'Correct! The flag is DH{%s}.',
    b'filter': b'Wrong!'
}
```

And the initial rule was:

```python
rules[b'line'] = [
    [b'filter'],
    [b'correct']
]
```

Because a rule is an OR of its lines, `line` effectively means:

```text
line = filter OR correct
```

So the input eventually reaches either the `filter` branch or the `correct` branch.

The `correct` rule consists of 64 `any` values:

```python
rules[b'correct'] = [
    [
        b'any', b'any', b'any', ...
    ]
]
```

There are exactly 64 of them.

Therefore, once we avoid the `filter` condition, the 64 hexadecimal characters become the `%s` part of:

```text
DH{%s}
```

The important part is therefore not to directly satisfy `correct`.

Instead, we need to make **every condition in `filter` false**.

---

# 7. First Attempt: Treating Filter Entries as Flag Positions

The `filter` rule contained 91 lines:

```python
len(rules[b'filter']) == 91
```

while the flag body has only 64 characters.

My first idea was to assume that the first 64 filter entries corresponded directly to the 64 input characters.

I calculated the set of possible characters for each filter entry:

```python
cands = [
    set(ANY)
    for _ in range(len(rules[b'filter']))
]

for i in range(len(rules[b'filter'])):
    line = rules[b'filter'][i]

    for node in line:
        cands[i] = cands[i].intersection(
            get_set(node)
        )
```

Then, because we want the filter condition to be false, I looked at the complement:

```python
correct = [[] for _ in range(64)]

for i in range(64):
    correct[i] = list(
        ANY.difference(cands[i])
    )

    print(i, b''.join(correct[i]))
```

The beginning of the result looked like:

```text
0  caf47b8e5961d
1  8c3afe52076d
2  c3ae5249071b
3  83df5249061b
4  d
5  7
6  4
7  3dafe924076b
8  c3af2407b8e5961d
9  c3af240b8e5961d
...
```

Some positions immediately produced one character:

```text
4  d
5  7
6  4
```

but most positions had many possibilities.

So this interpretation was obviously incomplete.

The 91 filter conditions were somehow interacting with the 64 input characters rather than corresponding to them one-to-one.

---

# 8. The Important Observation: 91 Constraints → 64 Characters

The key was to stop treating every filter line as an independent character position.

Instead, I processed the candidate sets sequentially.

The idea is simple.

There are 16 possible hexadecimal characters:

```text
0 1 2 3 4 5 6 7 8 9 a b c d e f
```

If a combined filter set contains 15 characters, then exactly **one character is missing**.

That missing character is the value which makes the corresponding condition false.

So I merged consecutive filter candidate sets until the accumulated set contained 15 characters.

```python
filters = []

current = set(cands[0])

for i in range(1, len(cands)):

    assert len(current) < 16

    if len(current) == 15:
        filters.append(current)

        current = set(cands[i])

    else:
        current = current.union(cands[i])

filters.append(current)
```

Then I verified the result:

```python
assert len(filters) == 64

for f in filters:
    assert len(f) == 15
```

This was the important sanity check.

The 91 original filter constraints collapsed into exactly:

```text
64 groups
```

and every group contained:

```text
15 / 16 possible hexadecimal characters
```

So each group had exactly one missing character.

That is exactly what we need for a 64-character hexadecimal flag.

---

# 9. Recovering the Flag

Now the actual extraction is almost trivial.

For each group:

```python
ANY - filter_set
```

contains exactly one character.

So:

```python
flag = b''.join(
    [
        list(ANY.difference(f))[0]
        for f in filters
    ]
)

print(flag)
```

The result is the 64-character hexadecimal string used as:

```text
DH{<64 hexadecimal characters>}
```

The important thing here is that we never needed to brute-force `16^64` possible strings.

The rule graph itself gives enough information to determine each character independently after the 91 filter conditions are grouped correctly.

---

# 10. Why the Set Reduction Works

It is worth explaining why the `get_set()` approach is valid.

Suppose we have:

```text
R = (A AND B) OR (C AND D)
```

If:

```text
S(A) = {0,1,2}
S(B) = {1,2,3}
```

then:

```text
S(A AND B)
    = {0,1,2} ∩ {1,2,3}
    = {1,2}
```

Likewise, if:

```text
S(C) = {2,3}
S(D) = {3,4}
```

then:

```text
S(C AND D)
    = {3}
```

and therefore:

```text
S(R)
    = {1,2} ∪ {3}
    = {1,2,3}
```

This exactly matches the recursive implementation:

```python
line_set = set(ANY)

for child in line:
    line_set &= get_set(child)

result |= line_set
```

The only slightly confusing part is that we are calculating the **set of values for which a rule evaluates to true**, and later taking its complement because the goal is to make `filter` evaluate to false.

---

# 11. Alternative Approach: Rebuilding the Boolean Expression

After solving it using sets, I also looked at a more general approach using symbolic constraints.

Instead of reducing each node to a character set, we can assign a Z3 integer variable to every input character:

```python
from z3 import *

N = 64

uinput = [
    Int(f'uinput[{i}]')
    for i in range(N)
]

s = Solver()

for i in range(N):
    s.add(
        And(
            uinput[i] >= 0,
            uinput[i] < 16
        )
    )
```

Here:

```text
0  = '0'
1  = '1'
...
10 = 'a'
...
15 = 'f'
```

The difficult part is figuring out which input indices each nested rule corresponds to.

Because a child rule can consume multiple input characters, I recursively calculated the input span of each rule.

```python
def assign_input_ranges(root="filter"):
    heirarchy.clear()

    def dfs(node, start_idx):
        if node in heirarchy:
            return heirarchy[node]

        max_span = 0

        for line in rules[node]:

            local_idx = start_idx

            for token, num in line:

                if num == 0:
                    child_start, child_end = dfs(
                        token,
                        local_idx
                    )

                    span = (
                        child_end -
                        child_start +
                        1
                    )

                    local_idx += span

                else:
                    local_idx += 1

            span_total = local_idx - start_idx

            max_span = max(
                max_span,
                span_total
            )

        heirarchy[node] = (
            start_idx,
            start_idx + max_span - 1
        )

        return heirarchy[node]

    dfs(root, 0)
```

Once the ranges are known, each leaf node can be translated into a Z3 condition:

```python
uinput[st + idx] == int(val, 16)
```

and the entire rule tree can be reconstructed as:

```text
OR(
    AND(...),
    AND(...),
    ...
)
```

The source implementation follows exactly this general approach: assign ranges to the nested rules, rebuild the boolean expressions, and push them upward toward `filter`.

For example:

```python
for line in rules[curr]:
    subconds = []

    for idx, (val, _) in enumerate(line):
        if val != 'any':
            subconds.append(
                uinput[st + idx] == int(val, 16)
            )

    line_clauses.append(
        And(*subconds)
    )

meth[curr] = Or(*line_clauses)
```

This produces a symbolic representation of the entire rule tree.

---

# 12. Solving the `filter` Constraint

Since `filter` is the branch that produces:

```text
Wrong!
```

we want:

```python
Not(meth['filter'])
```

The basic constraint is therefore:

```python
s.add(Not(meth[evaluation]))
```

where:

```python
evaluation = 'filter'
```

The implementation also explicitly adds the negation of each filter line:

```python
line_clauses = []

for line in rules[evaluation]:

    subconds = []

    for node, _ in line:
        subconds.append(meth[node])

    line_clauses.append(
        And(*subconds)
    )

for line in line_clauses:
    s.add(Not(line))
```

Then Z3 can search for an input satisfying the constraints.

In principle, this is a much more general solution than the set-based approach.

However, there was one annoying issue.

Some models returned by the simplified symbolic constraints did not satisfy all of the original checks when passed through the actual `check()` implementation. Because of this, the solver script also re-evaluated candidate strings against the original checker and added additional constraints when necessary.

For this particular challenge, the set-based reduction was therefore much cleaner.

---

# 13. Final Solver

The complete data-oriented solver can be kept surprisingly small once the rules have already been dumped:

```python
ANY = set(b'0123456789abcdef')


def get_set(k):
    if len(k) == 1:
        return {k}

    if k == b'any':
        return set(ANY)

    result = set()

    for line in rules[k]:
        line_set = set(ANY)

        for child in line:
            line_set &= get_set(child)

        result |= line_set

    return result


# Reduce every filter line to its possible characters
cands = []

for line in rules[b'filter']:
    possible = set(ANY)

    for node in line:
        possible &= get_set(node)

    cands.append(possible)


# Merge the 91 filter constraints into
# 64 groups.
filters = []

current = set(cands[0])

for i in range(1, len(cands)):
    assert len(current) < 16

    if len(current) == 15:
        filters.append(current)
        current = set(cands[i])
    else:
        current |= cands[i]

filters.append(current)


# Sanity checks
assert len(filters) == 64

for f in filters:
    assert len(f) == 15


# Exactly one hexadecimal character is missing
flag = b''.join(
    list(ANY - f)[0]
    for f in filters
)

print(flag)
```

The important assertions are not strictly necessary, but I would definitely keep them when solving the challenge.

They make it immediately obvious if the interpretation of the rule structure is wrong.

In particular:

```python
assert len(filters) == 64
```

is a very strong indication that the 91 filter rules have been grouped correctly.

And:

```python
assert len(f) == 15
```

means every group leaves exactly one possible answer.

---

# 14. Takeaways

The biggest lesson from this challenge was that I didn't necessarily need to reverse every part of the binary.

The binary looked complicated because the rule graph was intentionally made complicated, but the actual data structure was regular.

The solve can be summarized as:

```text
                 ┌────────────────────┐
                 │      Binary        │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Locate rules table │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │  GDB memory dump   │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Python rule dict   │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ OR of AND clauses  │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Recursive set      │
                 │ reduction          │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ 91 filter lines    │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ 64 groups × 15     │
                 │ possible chars     │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │ Missing character  │
                 │ from each group    │
                 └─────────┬──────────┘
                           │
                           ▼
                    64-char hex flag
```

The alternative Z3 solution is useful if the rule system becomes more complicated or if the individual character-set reduction is no longer sufficient. But for this challenge, dumping the data and treating the rules as a small boolean algebra was enough.

The part I liked most was that the seemingly arbitrary numbers — **91 filter conditions and 64 flag characters** — eventually lined up once the filter conditions were accumulated correctly.

That was the point where I knew the interpretation was probably right.
