# crackme03 — Mini LLM Sentinel

A reverse engineering (RE) solution for `crackme03.exe`. The analysis is static, in Ghidra. A test run under Wine confirms each result.

- Sample: `crackme03.exe`, PE32+ x86-64 console, MinGW GCC
- SHA-256: `bd758259be76d9fa3eddde7ae4cd56f417d076fc84496090e3dfe701fd68aaef`
- Ghidra project: `EVA`, program `/crackme03.exe`
- Valid password (one of many): `AI-K1flo0E026Iz!`

The `.exe` is not in this repository.

## Results

| Test under Wine | Result |
|---|---|
| Original file, password `AI-K1flo0E026Iz!` | `ACCEPT (confidence 0.97)`, `ACCESS GRANTED` |
| Sentinel patch, same password | `ACCEPT (confidence 0.97)`, no sentinel output |
| Score patch, input `xxxxxxxxxxxxxxxx` | `ACCEPT (confidence 0.00)`, the sentinel does not detect it |
| Original file, `winedbg` attached at the prompt | `HOSTILE R_FLAGS`, exit code 3 |
| Sentinel patch, `winedbg` attached, valid password | `ACCESS GRANTED`, exit code 0 |

`model.py` gives 0.97 for the example, the same as the real program. Over 40 random valid passwords, `model.py` and the binary print the same two-digit score in 40 of 40 cases.

## Files

| File | Use |
|---|---|
| `model.py` | Python copy of the password check. It reads the tables from the `.exe`. |
| `solve.py` | Finds random passwords that the model accepts. Also tests three bad inputs. |
| `gen_sample.py` | Writes a random sample of valid passwords. Arguments: count (default 10 000), output file, maximum `d` (default 0). |
| `valid_passwords_sample.txt` | 10 000 valid passwords with `d = 0`. The lowest score is 0.971. |
| `patch_sentinel.py` | Writes a copy of the `.exe` with the sentinel disabled. |

Run the scripts with `pefile` from `uvx`:

```bash
uvx --from pefile python solve.py
uvx --from pefile python patch_sentinel.py /path/to/output.exe
```

The scripts read the sample from `~/Downloads/Crackmes/6abd98190885f990699dc084/crackme03.exe`. Change the path at the top of each script if the sample is in a different location.

## Functions

| Address | Name | Role |
|---|---|---|
| `0x14001c180` | `main` | Shows the banner, starts the sentinel thread, and asks for the password 5 times. |
| `0x140004360` | `score_password_mlp` | Calculates the password features and runs the neural network. |
| `0x140004b30` | `print_verdict` | Decrypts and prints the `[guard-ai] verdict` line. |
| `0x140001490` | `sentinel_scan` | Runs one sentinel scan. Returns 1 for a hostile environment. |
| `0x140001b00` | `sentinel_thread` | Calls `sentinel_scan` every 1.2 s. |
| `0x140002050` | `collect_sensors` | Reads the anti-debug sensors. |
| `0x140003120` | `sensors_to_tokens` | Changes the sensor values into 11 tokens. |
| `0x1400034a0` | `llm_generate` | The small language model. Generates the verdict token. |
| `0x140003040` | `token_to_semantic_id` | Maps a token to its meaning through a table. |
| `0x140002e50` | `sentinel_fire_exit` | Prints `HOSTILE ENVIRONMENT detected!` and calls `ExitProcess(3)`. |
| `0x1400033f0` | `decrypt_llm_weights` | Decrypts the weights of the language model with xorshift32. |
| `0x140005450` | `check_code_integrity` | Compares code in memory with the files on disk. Gives the `sys`, `self` and `text` values. |
| `0x1400057f0` | `load_disk_images` | Reads the own `.exe` and the system DLL files from disk. |
| `0x14000d8d0` | `tanhf` | `tanh` for `float`. |
| `0x14000da20` | `expf` | `exp` for `float`. |

## The password check

`score_password_mlp` is a small neural network: 6 inputs, 8 hidden units with `tanh`, and 1 output with sigmoid. The program accepts a password when two conditions are true:

1. The length is 16.
2. The score is 0.5 or more.

### Inputs

| Input | Value |
|---|---|
| f0 | 1.0 if the password starts with `AI-`, ends with `!`, and has only printable characters |
| f1 | `max(0, 1 - abs((byte sum mod 256) - 0x65) / 64)` |
| f2 | 1.0 if the password has more than 3 digits |
| f3 | Count of characters that add a new bit / 16 (see the note below) |
| f4 | Number of upper-case letters / 16 |
| f5 | Number of lower-case letters / 16 |

**Note on f3.** The code does not count distinct characters. It keeps one bit for each group of 8 codes, in a 32-byte table indexed by `c >> 3`. It tests the bit with `1 << (c >> 3)`, but it uses only the low 8 bits of that mask. Thus:

- A character with code 64 or more (`a` to `z`, `A` to `Z`, most symbols) always adds 1, even when it repeats.
- A character with code below 64 adds 1 only the first time its group `c >> 3` appears. Characters in one group, such as `0` and `1`, share one count.

For `AI-K1flo0E026Iz!` the count is 12, not 14, so f3 = 0.75. The score is 0.9727 and the program prints 0.97. `model.py` uses the same rule.

A shuffle puts the 6 inputs in a different order before the network reads them. The order is `[1, 2, 0, 5, 3, 4]`.

### Rule for a valid password

`AI-` + 12 letters and digits + `!`. The sum of all 16 bytes, mod 256, must be `0x65`. Use more than 3 digits and many different characters.

### The math of a valid password

All numbers in this section come from `model.py`, with the real weights.

#### Step 1: the network

The network calculates one number `z`:

```
h[j] = tanh( sum_i Wh[j][i] * f[i] + bh[j] )     j = 0..7
z    = sum_j Wo[j] * h[j] + bo                   bo = -1.536
score = 1 / (1 + exp(-z))
```

The score is 0.5 or more when `z ≥ 0`. Thus the password must give `z ≥ 0`.

#### Step 2: which inputs are important

Start with the valid password `AI-K1flo0E026Iz!` (`z = +3.57`). Change one input at a time:

| Change | z | Score | Result |
|---|---|---|---|
| none | +3.57 | 0.973 | accept |
| f0 = 0 (no `AI-` or no `!`) | -4.03 | 0.017 | reject |
| f1 = 0 (wrong byte sum) | -18.51 | 0.000 | reject |
| f2 = 0 (3 digits or fewer) | -3.47 | 0.030 | reject |
| f3 = 0 (no counted characters) | +3.03 | 0.954 | accept |
| f4 = 1 (upper case) | +2.98 | 0.952 | accept |
| f5 = 1 (lower case) | +3.13 | 0.958 | accept |

Inputs f0, f1 and f2 must all be 1. Inputs f3, f4 and f5 change `z` by less than 0.7, so they are almost not important. With all inputs at 0, `z = -21.1`.

#### Step 3: why f1 is the most important input

Two hidden units do most of the work. Each one is an AND gate on f1:

| Unit | Weight on f1 | Bias | Output weight |
|---|---|---|---|
| h6 | +4.54 | -5.04 | +6.83 |
| h0 | +3.28 | -3.86 | +5.16 |

When f1 = 1, the sum is about 0 and `tanh` is near 0. When f1 = 0, the sum is about -5 and `tanh` is near -1. Then `6.83 × (-1)` and `5.16 × (-1)` pull `z` down by about 12. This is why a wrong byte sum gives `z = -18.5`.

#### Step 4: the byte sum

The code calculates the distance `d`:

```
d  = abs( (sum of all bytes mod 256) - 0x65 )
f1 = max(0, 1 - d/64)
```

With f0, f2 and the other inputs as in the example, `z` falls when `d` increases:

| d | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|---|
| z | +3.57 | +2.70 | +1.80 | +0.90 | -0.01 | -0.92 | -1.81 |

For this password, `d` must be 3 or less. At `d = 4`, `z = -0.01` and the score is 0.498, which rejects. The byte sum mod 256 must be in the range `0x62` to `0x68`. Use `d = 0` for a good margin. Other passwords can pass at `d = 4`: see the score table below.

#### Step 5: calculate the middle 12 characters

The fixed parts have a known sum:

```
'A' + 'I' + '-' + '!' = 65 + 73 + 45 + 33 = 216 = 0xD8
```

The middle 12 bytes must give the rest:

```
middle sum ≡ 0x65 - 0xD8 ≡ -0x73 ≡ 0x8D = 141   (mod 256)
```

Twelve letters and digits (bytes 48 to 122) give a sum from 576 to 1464. In this range, the possible values are 141 + 256k:

```
653, 909, 1165, 1421
```

#### Step 6: example

`K1flo0E026Iz` has a byte sum of 909. Then:

```
216 + 909 = 1125 = 0x465
0x465 mod 256 = 0x65      ->  d = 0, f1 = 1
```

The other inputs:

- f0 = 1: the password starts with `AI-`, ends with `!`, and all characters are printable.
- f2 = 1: the digits are `1 0 0 2 6`, that is 5 digits, more than 3.
- The length is 16.

The result is `z = +3.57` and score 0.973. The real program prints `confidence 0.97`.

#### Number of valid passwords

The middle has 12 characters. Each one is one of 94 printable characters (33 to 126):

```
94^12                      ≈ 4.8 × 10^23
× P(4 digits or more)      ≈ 0.031
× 9/256 (d ≤ 4)            ≈ 0.035
= valid passwords          ≈ 5 × 10^20
```

This is an estimate. Inputs f3 to f5 can change the result when `d` is 3 or 4. A list of all valid passwords needs about 9 zettabytes, so the repository holds only a random sample. With `d ≤ 4`, `gen_sample.py` found 10 000 valid passwords in 7 798 875 random tries, a rate of 0.13 %. This rate agrees with the estimate (0.11 %).

#### Score of 0.90 or more

The ranges come from 20 000 random valid passwords for each `d`. Each password has at least 4 digits and the byte sum that the rule requires.

| d | Byte sum mod 256 | Score (min to max) | Share at 0.50 or more |
|---|---|---|---|
| 0 | `0x65` | 0.971 to 0.978 | 100 % |
| 1 | `0x64`, `0x66` | 0.933 to 0.948 | 100 % |
| 2 | `0x63`, `0x67` | 0.853 to 0.881 | 100 % |
| 3 | `0x62`, `0x68` | 0.698 to 0.757 | 100 % |
| 4 | `0x61`, `0x69` | 0.486 to 0.551 | 91 % |

Thus a score of 0.90 or more needs `d = 0` or `d = 1`. The spread comes from f3 to f5. It is 0.006 at `d = 0` and 0.015 at `d = 1`.

The file `valid_passwords_sample.txt` holds only passwords with `d = 0`. The generator needed 70 597 325 tries for 10 000 passwords. Five random lines passed in the real program, with a confidence of 0.97 or 0.98.

#### Recipe

1. Write `AI-` and `!`.
2. Select 12 letters and digits for the middle. Include 4 digits or more.
3. Add the bytes of the 12 characters.
4. Change one character until the sum is 653, 909, 1165 or 1421.
5. Make sure that the length is 16.

### Tables in the binary

| Address | Content | Decryption |
|---|---|---|
| `0x14006c720` | 65 float32 weights | dword XOR xorshift32, seed `0xeb78774d` |
| `0x14006c540` | 256-byte character class table | `byte[i] ^ (i*0x33 + 0x5b)` |
| `0x14006c713` | Prefix `AI-` | `byte[i] ^ (0x97 + 0x41*i)` |
| `0x14006c840` | `1.0`, `1/16`, `1/64` | none |
| `0x14006c860` | Threshold `0.5` | none |

Layout of the weights: `W[0..47]` hidden weights (8 rows of 6), `W[48..55]` hidden biases, `W[56..63]` output weights, `W[64]` output bias.

The class table gives 4 bits for each byte: bit 0 = digit, bit 1 = upper case, bit 2 = lower case, bit 3 = printable.

### Key byte

The decryption of the prefix and the suffix uses the byte at `0x140110ca0`. This byte is in `.bss`, and no instruction writes it. Thus its value is 0. With 0, the decrypted values are readable (`AI-`, `!`, and the 4 character classes). This result confirms the value.

## The sentinel

1. `collect_sensors` reads the sensors:
   - the PEB at `gs:[0x60]`: `BeingDebugged` (+0x2), `NtGlobalFlag & 0x70` (+0xBC), and the heap flags
   - the debug registers DR0 to DR3, through `GetThreadContext`
   - `int3` bytes, timing, and window titles
2. `sensors_to_tokens` changes the values into 11 tokens, for example `BD0 NG0 HP0 DR0 I30 WT0 A0 B0 S0 H0 M0`.
3. `llm_generate` reads the tokens and generates one verdict token.
4. `sentinel_scan` reads the verdict:
   - `0x1e` (HOSTILE): calls `sentinel_fire_exit`
   - `0x1d` (UNSURE): scans one more time, then accepts the result as clean
   - any other token: clean

The program runs a scan at start, before each password, and in the sentinel thread.

Set `CRACKME_AI_VERBOSE=1` to see the tokens and the sensor values. Set `CRACKME_LLM_SELFTEST=1` to run the self-test of the model.

### Test with a debugger

`winedbg` cannot show the output of a program that it starts. Thus the test attaches `winedbg` to a running program:

1. Start the program with `CRACKME_AI_VERBOSE=1`. Connect its input to a named pipe, so that it waits at the password prompt.
2. Get the Wine process ID with `winedbg --command "info proc"`.
3. Attach with a command file that holds `attach 0x<pid>` and `cont`.

The sentinel thread scans again after about 1.2 s. The result of the scan:

```
ctx: ... SCAN BD1 NG0 HP0 DR0 I30 WT0 A0 B0 S0 H0 M0
generated: HOSTILE R_FLAGS EOS | min_margin=5.94 | sensors: bd=1 ...
[AI] sentinel verdict: HOSTILE ENVIRONMENT detected!
[AI] evidence: ai=R_FLAGS | sensors: flags=1/0/0 dr=0 int3=0 ...
```

The attach sets `BeingDebugged` in the PEB, so the token changes from `BD0` to `BD1`. The model then generates `HOSTILE` and gives the reason `R_FLAGS`. The program stops with exit code 3. The other sensors stay at 0 under Wine.

### Code integrity sensors

`check_code_integrity` gives three values. Each one compares code in memory with a copy of the file on disk.

| Value | What it compares |
|---|---|
| `sys` | The first 16 bytes of some API functions in system DLLs. A change shows a hook. |
| `self` | A list of the program's own functions. |
| `text` | All of `.text`. The value is the count of bytes that differ. The count stops at `0xffff`. |

At start, `load_disk_images` calls `GetModuleFileNameA` and reads the own `.exe` into `g_self_file_buf` (`0x140110d28`). It also reads the system DLLs from `GetSystemDirectoryA`.

Thus a patch in the file on disk changes both copies, and `text` stays 0. A patch in memory changes only one copy.

Test: attach `winedbg`, write `B0 01 90` at `0x140004a0d` in memory, then detach. The next scan gives:

```
sensors: bd=1 ... sys=0 self=1 text=3 sysc=5
```

`text=3` is the count of the 3 changed bytes. `self=1` shows that `score_password_mlp` is in the `self` list. Wine kept `bd=1` after the detach, so the reason for the verdict was `R_FLAGS`.

Lesson: a check against the file on disk does not see a patch in the file. Patch the file, not the memory.

### Patches

| Patch | Address | File offset | Bytes |
|---|---|---|---|
| Disable the sentinel | `0x140001490` | `0x890` | `41 55 41` → `31 C0 C3` (`xor eax,eax; ret`) |
| Accept every 16-character input | `0x140004a0d` | — | `0F 93 C0` → `B0 01 90` (`setnc al` → `mov al,1`) |

The second patch works only for an input of 16 characters. At `0x140004a03`, a `JNZ` jumps over the `SETNC` when the length is not 16.

## Lessons

1. **Read the assembly when the decompiler shows a cast.** The decompiler showed `(float)(x ^ s)` for the weights. The instruction is `MOV dword [RCX-4], EDX`, which copies the bits. Ghidra showed a cast only because it typed the array as `float`.
2. **Sigmoid in x86.** `XORPS` with `0x80000000` changes the sign. Then `1/(1+exp(-z))` gives the score. A score of 0.5 or more means `z ≥ 0`.
3. **Fisher-Yates with a pointer.** The first version of `model.py` used the wrong swap index. The pointer `pbVar37[4]` starts at `perm[4]`, so the index is `n-1`, not `n`.

## Open items

- The memory test did not give a HOSTILE verdict from `text` alone. Wine kept `BeingDebugged` set after the detach, so `R_FLAGS` was the reason. A test without a debugger needs a separate program that calls `WriteProcessMemory`.
