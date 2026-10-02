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

The model in `model.py` gives the same score as the real program (0.97).

## Files

| File | Use |
|---|---|
| `model.py` | Python copy of the password check. It reads the tables from the `.exe`. |
| `solve.py` | Finds random passwords that the model accepts. Also tests three bad inputs. |
| `patch_sentinel.py` | Writes a copy of the `.exe` with the sentinel disabled. |

Run the scripts with `pefile` from `uvx`:

```bash
uvx --from pefile python solve.py
uvx --from pefile python patch_sentinel.py /path/to/output.exe
```

The scripts read the sample from `~/Downloads/6abd98190885f990699dc084/crackme03.exe`. Change the path at the top of each script if the sample is in a different location.

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
| f3 | Number of different characters / 16 |
| f4 | Number of upper-case letters / 16 |
| f5 | Number of lower-case letters / 16 |

A shuffle puts the 6 inputs in a different order before the network reads them. The order is `[1, 2, 0, 5, 3, 4]`.

### Rule for a valid password

`AI-` + 12 letters and digits + `!`. The sum of all 16 bytes, mod 256, must be `0x65`. Use more than 3 digits and many different characters.

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

- The tests did not use a real debugger, so no test showed the HOSTILE verdict. Use x64dbg on Windows, or `winedbg`.
- The `text` sensor did not detect a patch in the file. Its exact check is not known.
