# Too Many Questions — Write-up

**Category:** Reversing + Misc  
**Event:** Dreamhack Invitational Quals 
**Flag format:** `DH{...}`

## 1. Challenge Overview

The challenge provides the following files:

- `main`: A stripped ELF x86-64 PIE binary written in C++.
- `gen.py`: The script used to generate the challenge environment.
- `run.sh` and `Dockerfile`: Scripts used to launch and terminate the containers.
- `flag_hint.txt`: An MD5 hash.
- `tcpdump/tcpdump.pcap`: The network capture containing the actual challenge data.

The challenge description is:

> Who in the world finds and verifies the flag this way? It's right here.

The first important step is understanding how the flag is generated.

Looking at `gen.py`, we find:

```python
flag_inner = hashlib.sha256(os.urandom(10)).hexdigest()
flag = f"DH{{{flag_inner}}}"

key = hashlib.sha256(os.urandom(10)).hexdigest()[:16]

for i in range(32):
    flag_part = flag_inner[2 * i:2 * i + 2]
````

The flag consists of 64 hexadecimal characters.

The script creates 32 workers, and each worker receives exactly two hexadecimal characters, corresponding to one byte of the flag.

All workers share the same AES key.

The script also generates:

python

```python
flag_hint = hashlib.md5(flag.encode()).hexdigest()
```

Therefore, `flag_hint.txt` contains the MD5 hash of the complete flag, including the `DH{}` wrapper.

Our objective is to reconstruct the 32 bytes from the network capture.

Interestingly, we do not need to recover the AES key.

## 2. Understanding the Encryption

The binary implements AES-128 manually.

The encryption key is obtained using:

cpp

```cpp
getenv("KEY")
```

Since the key consists of 16 hexadecimal characters, brute-forcing it would require searching a space of:

$$
16^{16}=2^{64}
$$

This is not practical.

However, examining the encryption function reveals something much more interesting:

cpp

```cpp
void encrypt(uint8_t *buf, size_t len, bool decrypt) {
    AES ctx;
    AES_init(&ctx, g_key);

    assert(len % 16 == 0);

    do {
        len -= 16;

        decrypt
            ? aes_decrypt_block(&ctx, buf + len)
            : aes_encrypt_block(&ctx, buf + len);

    } while (len != 0);
}
```

Each 16-byte block is encrypted independently.

There is no chaining, IV, or nonce.

In other words, the encryption mode is ECB.

Every UDP payload is exactly 32 bytes, meaning each message consists of two AES blocks.

This gives us an important property:

$$
P_1=P_2 \implies E(P_1)=E(P_2)
$$

Even without knowing the encryption key, identical plaintext blocks always produce identical ciphertext blocks.

Consequently, we can analyze relationships between encrypted messages without decrypting them.

## 3. Cleaning the PCAP

Before analyzing the protocol, we need to correctly extract the packets.

The capture contains:

text

```text
Total packets: 40,760
Unique messages: 20,380
```

The tcpdump container uses `network_mode: host` and captures traffic with `-i any`.

As a result, each logical UDP message appears exactly twice in the capture.

We can remove duplicates using a key such as:

python

```python
(src, dst, sport, dport, payload)
```

After deduplication:

text

```text
Raw packets:       40,760
Unique messages:  20,380
```

There is another subtle issue with packet extraction.

Using tshark:

bash

```bash
tshark -r tcpdump.pcap -T fields -e data.data
```

produces 40,760 lines, but 938 of them are empty.

The packets are not actually missing their payloads. The heuristic dissector simply classifies some packets as other protocols and does not create a `data` layer for them.

Using Scapy or parsing the UDP packets directly confirms that all 40,760 packets contain a 32-byte payload.

This is important because silently missing packets can corrupt later statistics.

After correct deduplication, we have 20,380 logical messages.

## 4. Recovering the Message Structure

We can now examine the two 16-byte ciphertext blocks independently.

The statistics are:

| Property | Count |
| --- | --- |
| Total unique 16-byte blocks | 448 |
| First-block types | 192 |
| Second-block types | 256 |

The two sets are completely disjoint.

The second block has exactly 256 distinct ciphertext values.

This strongly suggests that the second block represents a single byte, since:

$$
2^8=256
$$

Indeed, the second block contains the encrypted threshold used in each comparison.

Let us call it the tail block.

The first block has 192 distinct values:

$$
192=32\times6
$$

This corresponds to 32 workers, each having six possible message types.

The first block contains information identifying the sender and the message type.

The reconstructed plaintext format is:

Query:

text

```text
[header] [sender ID] "Query is: " '?' [operator]
```

Response:

text

```text
[header] [sender ID] "Query is: " ['y'/'n'] [operator]
```

The second block contains the decimal representation of the threshold.

The actual format is:

text

```text
Block 0: 16 bytes
Block 1: 16 bytes
```

The first block identifies the worker and the query/response type, while the second block represents the threshold.

The key observation is that the threshold is shared globally.

Thus, every worker uses the same 256 possible tail blocks, regardless of its identity.

This transforms the problem from recovering 32 independent encrypted values into recovering one global mapping between 256 ciphertext blocks and the integers from 0 to 255.

## 5. Pairing Queries and Responses

A worker sends a query to another worker, and the receiver responds using the same threshold.

Because ECB preserves equality, the query and response have identical second ciphertext blocks.

Therefore, we can pair messages using:

python

```python
query_key = (src, dst, tail_block)
answer_key = (dst, src, tail_block)
```

We also preserve packet order when pairing repeated exchanges.

The result is:

text

```text
Logical messages:       20,380
Query/answer exchanges: 10,190
Unmatched messages:     0
```

There are 992 communicating worker pairs:

$$
32\times31=992
$$

This means every worker communicates with every other worker.

The first-block statistics can now be separated into:

| Message type | Total | Per worker |
| --- | --- | --- |
| Query blocks | 64 | 2 |
| Response blocks | 128 | 4 |
| Total | 192 | 6 |

Each worker has two query types and four response types.

The two query types correspond to the two comparison operators, `<` and `>`.

Each operator has two possible response classes: yes and no.

We can identify the query and response blocks by their roles in the paired exchanges, without decrypting them.

## 6. Understanding the Comparison Algorithm

The workers maintain a secret byte and repeatedly compare it against thresholds supplied by other workers.

Let:

- $s$ be the secret byte of the receiving worker.
- $t$ be the threshold.
- `y` represent a positive response.
- `n` represent a negative response.

The two query types are:

text

```text
?>t
?<t
```

Their meanings are:

$$
?>t \quad\Longrightarrow\quad s>t
$$

$$
?<t \quad\Longrightarrow\quad s<t
$$

The response rules are:

| Query | Response | Meaning |
| --- | --- | --- |
| `>t` | `y` | $s>t$ |
| `>t` | `n` | $s\leq t$ |
| `<t` | `y` | $s<t$ |
| `<t` | `n` | $s\geq t$ |

The worker updates its search interval according to these results.

For example:

cpp

```cpp
if (v == 'y' && op == '>')
    lo = n + 1;

else if (v == 'y' && op == '<')
    hi = n - 1;

else if (v == 'n' && op == '>')
    hi = n;

else if (v == 'n' && op == '<')
    lo = n;
```

The important detail is that the negative responses include equality in their boundaries.

This is what eventually allows us to identify the worker's exact secret.

## 7. Extracting Each Worker’s Secret Threshold

We now focus on one receiving worker.

It has four response block types:

- Two response types for the first comparison operator.
- Two response types for the second comparison operator.

For each operator, the two response classes partition the set of observed tail blocks into two groups.

When we compare the partitions produced by the two operators, an interesting pattern appears.

The four response classes form a 2×2 table.

Exactly three cells are populated.

Moreover, the remaining populated cell contains exactly one tail block.

This pattern occurs for all 32 workers.

The singleton tail block is the threshold corresponding to that worker's secret.

Why?

Consider the two relevant predicates:

$$
A=\{t\mid t<s\}
$$

and

$$
B=\{t\mid t\leq s\}
$$

Their difference is:

$$
B-A=\{s\}
$$

The two comparisons differ at exactly one threshold: the worker's own secret.

Therefore, the unique tail block isolated by the intersection pattern represents the encrypted version of the worker's secret.

Let us call it:

$$
eq\_tail(i)
$$

for worker $i$.

Extracting these blocks gives us the following result:

text

```text
Workers:                    32
Distinct eq_tail blocks:    30
```

Two pairs of workers share the same secret.

Importantly, this discovery does not require knowing any actual threshold values.

We only use ciphertext equality and the structure of the comparison responses.

## 8. Recovering the Global Ordering

At this point, we know the encrypted threshold corresponding to each worker's secret, but we still do not know the actual numerical values.

We need to recover the ordering of the 256 tail blocks.

The first challenge is that the ciphertext blocks themselves cannot be numerically compared.

Instead, we extract ordering constraints from the workers' comparison results.

For a worker with secret $s_m$, the two response classes partition the threshold space into lower and upper groups.

By comparing the classifications of the secret thresholds of different workers, we can infer their relative ordering.

Suppose worker $m$ classifies the secret threshold of worker $n$ as belonging to its lower group.

Then:

$$
s_n<s_m
$$

The reverse comparison must be consistent:

$$
s_m>s_n
$$

This antisymmetry allows us to propagate ordering information between the workers.

There is initially an ambiguity in the meaning of the two response classes: we do not know which class represents the lower side.

We can try both possible orientations and retain the assignments that produce an acyclic ordering.

After applying the consistency constraints, each worker has exactly two valid local labelings.

Propagating the constraints across the workers resolves the relative orientations, leaving only one global polarity ambiguity.

The resulting comparison graph contains:

text

```text
Direct comparison edges: 270
Direct contradictions:     0
Cycles after closure:       0
Distinct secret levels:    30
```

Thus, we recover a total ordering over the 30 distinct worker-secret values.

### Turning ordering into actual byte values

The tail blocks represent all 256 possible byte values, and their mapping to the values 0 through 255 is a bijection.

Therefore, the numerical value of a tail block is exactly its rank in the complete ordering:

$$
value(t)=|\{u\mid u<t\}|
$$

In other words, we do not need to decrypt the threshold blocks.

We only need to sort them.

The 30 recovered secret levels divide the threshold space into 31 buckets.

For each tail block, the comparison constraints determine which bucket it belongs to.

The results are:

text

```text
Distinct secret levels: 30
Number of buckets:      31
Uniquely determined:    240
Ambiguous:               16
```

The 16 ambiguous tail blocks cannot be completely localized using the available worker comparisons alone.

Some workers simply never queried thresholds that would distinguish these remaining possibilities.

However, the ambiguity is small enough to resolve using global constraints.

## 9. Resolving the Remaining Ambiguity with MD5

The remaining candidates can be represented as count vectors describing how many threshold blocks belong to each bucket.

Enumerating the possible assignments gives:

text

```text
Distinct count vectors: 3,096,576
Search space including both global polarities: 4,128,768
```

We can eliminate invalid assignments using the fact that all 256 byte values must appear exactly once.

One useful constraint is:

$$
\sum_i count_i=256
$$

We also apply the ordering and bucket-width constraints.

Finally, we reconstruct the candidate flag and compare its MD5 hash against `flag_hint.txt`.

The challenge provides:

text

```text
MD5("DH{" + flag_inner + "}")
```

This is a hash of the entire flag, not an independent oracle for each worker.

Consequently, testing 256 possibilities independently for every worker would be incorrect.

The initial idea of performing only:

$$
32\times256=8192
$$

tests does not work because changing even one byte changes the MD5 hash unpredictably.

Instead, we enumerate globally consistent assignments and use the MD5 hash to select the correct complete flag.

The result is:

text

```text
$ python3 cd_final.py

anchor=True
levels=30
ambiguous=16
search space=4128768

distinct count-vectors: 3096576

*** MATCH ***

MD5:
a5facb6e1f01e7f1a49f82057dc91892

real 0m13.2s
```

The resulting flag is:

text

```text
DH{...}
```

Its MD5 hash exactly matches the supplied hint.

## 10. Independent Verification

The MD5 match is the final selection mechanism, but there are also two useful independent consistency checks.

### 10.1. Boundary values 0 and 255

The binary generates thresholds using:

cpp

```cpp
char op = (get_random() & 1) ? '>' : '<';

uint8_t v = get_random() % (hi - lo);

if (op == '<')
    v += 1;

v += lo;
```

Since:

$$
0\leq lo\leq hi\leq255
$$

a `>` query can never use threshold 255.

Similarly, a `<` query can never use threshold 0.

We can use this property to identify the two extreme tail blocks.

The query-head relationships form exactly two connected components.

Each component contains 32 query heads and uses 255 of the 256 possible tail blocks.

The unused tail block in one component corresponds to one extreme, while the unused tail block in the other corresponds to the opposite extreme.

Comparing these blocks against the recovered classifications confirms that they represent 0 and 255.

This is an independent structural check, although it does not resolve the global polarity by itself.

Both polarities remain consistent with this observation.

### 10.2. Predicting equal secrets before knowing their values

The `eq_tail` extraction was performed without knowing any numerical threshold values.

Therefore, if two workers share the same `eq_tail`, we can predict that their secrets are equal before recovering their actual values.

The ciphertext analysis predicts exactly two pairs:

text

```text
Worker 4  == Worker 15
Worker 7  == Worker 20
```

After reconstructing the flag, these predictions are confirmed:

text

```text
Worker 4  == Worker 15 : ae
Worker 7  == Worker 20 : 0e
```

This is a particularly useful verification because the equality predictions were obtained before the actual byte values were known.

## 11\. Conclusion

The interesting part of this challenge is that AES-128 never needed to be broken.

The binary uses ECB encryption, which leaks equality between plaintext blocks.

Because every message has a fixed length of 32 bytes, the block boundaries also preserve the logical structure of the protocol.

This gives us two major pieces of information:

1. The first block identifies the worker and the comparison type.
2. The second block identifies the threshold.

Even though the AES key is unknown, ciphertext equality is enough to reconstruct the relationships between messages.

The workers repeatedly perform comparisons against one another's secret bytes.

By analyzing the comparison responses, we can identify each worker's secret threshold, recover the relative ordering of the secret values, and eventually assign numerical values to the encrypted threshold blocks.

The final ambiguity is resolved using the supplied MD5 hash.

The overall approach can be summarized as:

1. Correctly parse and deduplicate the PCAP.
2. Identify the two independent ECB blocks.
3. Use ciphertext equality to pair queries and responses.
4. Recover the two comparison operators and their response classes.
5. Extract each worker's secret threshold using the singleton intersection pattern.
6. Reconstruct the global ordering of the 256 encrypted thresholds.
7. Resolve the remaining ambiguous assignments using global constraints and the MD5 hint.

The key lesson is that encryption does not necessarily hide all useful information.

ECB preserves equality, and in a protocol built around repeated comparisons, equality relationships can reveal enough structure to reconstruct the underlying secret values.

The AES key remained unknown throughout the entire solution, and not a single ciphertext block needed to be decrypted.

```
```
