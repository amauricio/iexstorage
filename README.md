# IEXStorage

![IEXStorage](https://github.com/amauricio/iexstorage/blob/main/iexstorage.jpg?raw=true)

> Store payloads in the Internet Explorer URL history.

**iexstorage** is a technique for storing arbitrary data inside Internet Explorer's URL history. It can be used for persistence, data exfiltration, or as a stealthy communication channel. The project demonstrates how to encode and retrieve shellcode from IE history without writing anything to disk.

## Features

- Stores binary payloads by encoding them into hexadecimal URLs.
- Uses custom titles (keys) to tag and sequence URL fragments.
- Retrieves and reconstructs payloads from IE history.
- Optional in-memory shellcode execution.
- Minimal footprint using only native WinAPI.

## How It Works

1. Disables IE's first-run prompt via registry.
2. Launches an IE instance (`about:blank`) to initialize components.
3. Splits payloads into chunks and converts them to `iex://<hex>/` URLs.
4. Each chunk is stored in IE history with a key like `iexstorage#001`, `iexstorage#002`, etc.
5. URLs are later read, sorted by sequence, and decoded back to binary.

## Potential Use Cases

- 🧬 **Data Persistence**: Hide payloads in the registry and browser history without touching disk files.
- 💀 **Fileless Malware Techniques**: Load and execute shellcode entirely from memory using IE's native components.
- 🕵️ **Covert Channels**: Use browser history as an unexpected data store to exfiltrate or transfer information discreetly.
- 🔍 **Red Team Operations**: Simulate advanced attacker techniques or test detection of obscure storage channels.
- 🛠️ **Proof of Concept**: Demonstrate browser abuse and legacy application risks in corporate environments.

## Build

You can compile the project on Windows using Visual Studio or the Developer Command Prompt.

**Requirements:**

- Windows OS (< Win 10)
- C++ Compiler (MSVC recommended)
- Windows SDK
- Linked libraries:
  - `urlmon.lib`
  - `oleaut32.lib`
  - `ole32.lib`

### Compile Example

```bash
cl /EHsc iexstorage.cpp /link urlmon.lib oleaut32.lib ole32.lib
