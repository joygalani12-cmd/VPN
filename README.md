# VPN Client — Project Documentation

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Security Model](#4-security-model)
5. [Prerequisites](#5-prerequisites)
6. [Building the Project](#6-building-the-project)
7. [Usage](#7-usage)
8. [Code Structure & Walkthrough](#8-code-structure--walkthrough)
9. [Packet Format](#9-packet-format)
10. [Routing Logic](#10-routing-logic)
11. [Error Handling](#11-error-handling)
12. [Troubleshooting](#12-troubleshooting)
13. [Limitations & Future Work](#13-limitations--future-work)

---

## 1. Project Overview

This project is a **custom-built, lightweight VPN client for Windows** written in C++. It creates an encrypted network tunnel between the client machine and a remote VPN server using modern cryptographic primitives.

The design is inspired by WireGuard — sharing the same port (51820), crypto algorithms (X25519 + AES-256-GCM), and TUN driver (Wintun) — but is implemented from scratch as a standalone, minimal VPN solution.

### What It Does

- Creates a virtual network interface (`vpn0`) using the Wintun driver
- Performs a secure key exchange with the server using X25519 Elliptic Curve Diffie-Hellman
- Optionally authenticates the handshake using a Pre-Shared Key (PSK) to prevent MITM attacks
- Encrypts all outgoing traffic with AES-256-GCM before sending it to the server
- Decrypts all incoming traffic from the server and injects it back into the local network stack
- Reroutes the system's entire internet traffic through the VPN tunnel
- Gracefully restores routing on shutdown (Ctrl+C)

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT MACHINE                          │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────────┐    │
│  │   Apps    │───>│  Wintun TUN  │───>│  Sender Loop       │    │
│  │ (Browser, │    │  Adapter     │    │  (Main Thread)     │    │
│  │  curl...) │    │  "vpn0"      │    │                    │    │
│  └──────────┘    │  10.0.0.2    │    │  1. Read packet    │    │
│       ▲          └──────────────┘    │  2. Encrypt (GCM)  │    │
│       │                 ▲            │  3. Send over UDP   │────────> To Server
│       │                 │            └────────────────────┘    │     (port 51820)
│       │                 │                                      │
│       │          ┌──────────────┐    ┌────────────────────┐    │
│       │          │  Wintun TUN  │<───│  Receiver Thread   │    │
│       └──────────│  Adapter     │    │                    │<───────── From Server
│                  │  (inject)    │    │  1. Recv over UDP  │    │
│                  └──────────────┘    │  2. Decrypt (GCM)  │    │
│                                      │  3. Inject packet  │    │
│                                      └────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Outbound:** Application → OS routing → Wintun adapter → Sender Loop → Encrypt → UDP to Server
2. **Inbound:** Server → UDP packet → Receiver Thread → Decrypt → Wintun adapter → OS routing → Application

---

## 3. Technology Stack

| Component          | Technology                  | Purpose                                    |
|--------------------|-----------------------------|--------------------------------------------|
| Language           | C++ (Windows)               | Core implementation                        |
| TUN Driver         | Wintun (`wintun.dll`)       | Virtual network adapter                    |
| Encryption         | AES-256-GCM (OpenSSL)      | Authenticated encryption of tunnel traffic |
| Key Exchange       | X25519 ECDH (OpenSSL)      | Secure shared secret derivation            |
| Authentication     | HMAC-SHA256 with PSK        | Handshake authentication (anti-MITM)       |
| Transport          | UDP (port 51820)            | Tunnel protocol                            |
| Networking API     | Winsock2                    | Socket communication                       |
| Routing            | Windows `route` / `netsh`   | Traffic redirection                        |

---

## 4. Security Model

### 4.1 Key Exchange

The client and server perform an **X25519 Elliptic Curve Diffie-Hellman** key exchange:

1. Client generates an ephemeral X25519 key pair
2. Client sends its 32-byte public key to the server
3. Server sends its 32-byte public key back
4. Both sides independently derive the same 32-byte shared secret

This shared secret becomes the AES-256-GCM encryption key for the session.

### 4.2 PSK Authentication (Anti-MITM)

Without authentication, the key exchange is vulnerable to Man-in-the-Middle attacks. The PSK authentication step prevents this:

1. Both sides compute: `HMAC-SHA256(PSK, client_pub || server_pub)`
2. Both sides exchange their computed HMACs
3. Both sides verify the received HMAC matches their own

If an attacker substitutes their own public keys during the exchange, the HMAC inputs will differ (because the public keys are different), and since the attacker doesn't know the PSK, they cannot forge a valid HMAC.

> **Note:** The HMAC comparison uses OpenSSL's `CRYPTO_memcmp()` which is constant-time, preventing timing side-channel attacks.

### 4.3 Tunnel Encryption

All traffic is encrypted with **AES-256-GCM**, which provides:

- **Confidentiality** — data is encrypted with a 256-bit key
- **Integrity** — the 16-byte GCM authentication tag detects any tampering
- **Uniqueness** — each packet uses a random 12-byte IV generated by `RAND_bytes()`

### 4.4 Security Properties

| Property               | Status   | Mechanism                    |
|------------------------|----------|------------------------------|
| Forward Secrecy        | ✅ Yes   | Ephemeral X25519 keys        |
| Authenticated Handshake| ✅ Yes*  | PSK + HMAC-SHA256            |
| Encrypted Tunnel       | ✅ Yes   | AES-256-GCM                  |
| Integrity Protection   | ✅ Yes   | GCM authentication tag       |
| Replay Protection      | ⚠️ Partial | Random IVs prevent forgery  |

*When a PSK is provided.

---

## 5. Prerequisites

### Software Requirements

| Requirement       | Details                                          |
|-------------------|--------------------------------------------------|
| OS                | Windows 10/11 (64-bit)                           |
| Compiler          | MSVC (Visual Studio 2019+) or MinGW-w64 with C++17 |
| OpenSSL           | OpenSSL 3.x (headers + `libcrypto.lib`)          |
| Wintun Driver     | `wintun.dll` (download from https://www.wintun.net) |
| Privileges        | **Administrator** (required for Wintun and routing) |

### Files Required in Project Directory

```
VPN Project/
├── login.cpp          # Client source code
├── wintun.dll         # Wintun driver library
├── libcrypto.lib      # OpenSSL crypto library (for linking)
└── openssl/           # OpenSSL header files (or in system include path)
```

---

## 6. Building the Project

### Using MSVC (Visual Studio Developer Command Prompt)

```bash
cl /EHsc /std:c++17 login.cpp /I"<path-to-openssl-include>" /link /LIBPATH:"<path-to-openssl-lib>" libcrypto.lib ws2_32.lib Iphlpapi.lib /OUT:login.exe
```

### Using MinGW-w64

```bash
g++ -std=c++17 login.cpp -o login.exe -I<openssl-include> -L<openssl-lib> -lcrypto -lws2_32 -liphlpapi
```

### Using Visual Studio IDE

1. Create a new Console Application project
2. Add `login.cpp` to the project
3. Configure include paths for OpenSSL headers
4. Configure library paths and add: `libcrypto.lib`, `ws2_32.lib`, `Iphlpapi.lib`
5. Build in Release mode (x64)

---

## 7. Usage

### Command Syntax

```
login.exe <SERVER_IP> <GATEWAY_IP> [PSK_HEX]
```

### Parameters

| Parameter    | Required | Description                                         |
|-------------|----------|------------------------------------------------------|
| `SERVER_IP`  | Yes      | IP address of the VPN server                        |
| `GATEWAY_IP` | Yes      | IP address of your local router/default gateway     |
| `PSK_HEX`   | No       | 64-character hex string (32 bytes) pre-shared key   |

### Examples

```bash
# Find your gateway IP first
ipconfig | findstr "Default Gateway"

# Run without PSK (unauthenticated — shows warning)
login.exe 203.0.113.5 192.168.1.1

# Run with PSK (authenticated — MITM-resistant)
login.exe 203.0.113.5 192.168.1.1 4a8f2b...64chars...c3d1

# Generate a new PSK
openssl rand -hex 32
```

### Shutting Down

Press **Ctrl+C** to gracefully shut down the VPN. The program will:
1. Stop the sender and receiver loops
2. Restore the original default route via your gateway
3. Remove the server bypass route
4. Close the socket and clean up resources

---

## 8. Code Structure & Walkthrough

### File: `login.cpp`

The entire client is contained in a single file, organized into these sections:

| Section              | Lines (approx) | Description                                    |
|----------------------|----------------|------------------------------------------------|
| **Includes & Globals** | 1–28         | Headers, pragma libs, global state for cleanup |
| **Wintun API Types** | 30–40          | Function pointer typedefs for Wintun DLL       |
| **Crypto Functions** | 42–100         | `encrypt()` and `decrypt()` using AES-256-GCM  |
| **Key Exchange**     | 102–145        | `gen_keys()`, `get_pub()`, `derive()` for X25519 |
| **PSK Auth**         | 147–165        | `compute_handshake_hmac()` for HMAC-SHA256     |
| **Network Helper**   | 167–195        | `GetWintunIndex()` — finds Wintun adapter index |
| **Signal Handler**   | 197–220        | `ConsoleCtrlHandler()` — route restore on exit |
| **Main Function**    | 222–end        | CLI parsing, setup, handshake, tunnel loops    |

### Key Functions

#### `encrypt(plain, len, key, iv) → vector<uint8_t>`
Encrypts a plaintext buffer using AES-256-GCM. Returns `[IV(12) | Ciphertext | Tag(16)]`.

#### `decrypt(data, len, key) → vector<uint8_t>`
Decrypts an encrypted packet. Extracts IV and tag from the data, verifies the GCM tag, and returns the plaintext. Returns empty vector on auth failure.

#### `gen_keys() → EVP_PKEY*`
Generates an ephemeral X25519 key pair for the Diffie-Hellman exchange.

#### `get_pub(pk) → vector<uint8_t>`
Extracts the 32-byte public key from an EVP_PKEY.

#### `derive(priv, pub_bytes) → vector<uint8_t>`
Performs X25519 ECDH to derive a 32-byte shared secret from our private key and the peer's public key.

#### `compute_handshake_hmac(psk, psk_len, client_pub, server_pub) → vector<uint8_t>`
Computes HMAC-SHA256 over `client_pub || server_pub` using the PSK for handshake authentication.

#### `GetWintunIndex() → DWORD`
Enumerates network adapters to find the Wintun adapter's interface index (needed for route commands).

#### `ConsoleCtrlHandler(ctrlType) → BOOL`
Signal handler that restores the routing table and cleans up resources on Ctrl+C / window close.

---

## 9. Packet Format

### Encrypted Packet Structure

```
┌──────────┬─────────────────────┬──────────────────┐
│  IV (12) │  Ciphertext (N)     │  GCM Tag (16)    │
│  bytes   │  bytes              │  bytes           │
└──────────┴─────────────────────┴──────────────────┘
│<──────── Total: N + 28 bytes ─────────────────────>│
```

| Field      | Size     | Description                           |
|-----------|----------|----------------------------------------|
| IV         | 12 bytes | Random nonce, unique per packet       |
| Ciphertext | N bytes  | Encrypted IP packet                   |
| GCM Tag    | 16 bytes | Authentication tag for integrity check |

### Handshake Sequence

```
Client                              Server
  │                                    │
  │──── Client Public Key (32B) ──────>│
  │                                    │
  │<─── Server Public Key (32B) ───────│
  │                                    │
  │  [Both derive shared secret]       │
  │                                    │
  │──── HMAC(PSK, keys) (32B) ────────>│  (optional, if PSK)
  │                                    │
  │<─── HMAC(PSK, keys) (32B) ────────│  (optional, if PSK)
  │                                    │
  │  [Both verify HMACs match]        │
  │                                    │
  │════ Encrypted Tunnel Active ══════>│
```

---

## 10. Routing Logic

The client modifies the Windows routing table to redirect all traffic through the VPN:

### Routes Added

| Destination       | Mask              | Gateway      | Purpose                          |
|-------------------|-------------------|--------------|----------------------------------|
| `SERVER_IP/32`    | `255.255.255.255` | `GATEWAY_IP` | Bypass: VPN server via real gateway |
| `10.0.0.0/24`     | `255.255.255.0`   | `0.0.0.0`    | VPN subnet via Wintun adapter    |
| `0.0.0.0/0`       | `0.0.0.0`         | `10.0.0.1`   | Default route via VPN tunnel     |

### Routes Removed

| Route             | Reason                                    |
|-------------------|-------------------------------------------|
| Old `0.0.0.0/0`   | Replaced with VPN tunnel as default route |

### On Shutdown (Ctrl+C)

| Action                            | Purpose                          |
|-----------------------------------|----------------------------------|
| Delete `0.0.0.0/0` via VPN       | Remove tunnel default route      |
| Add `0.0.0.0/0` via `GATEWAY_IP` | Restore original internet access |
| Delete `SERVER_IP/32`            | Remove server bypass route       |

---

## 11. Error Handling

The client validates every critical operation and exits cleanly with an error message on failure:

| Check                          | Error Message                                          |
|-------------------------------|--------------------------------------------------------|
| CLI arguments missing         | Usage help printed                                     |
| PSK wrong length              | `PSK must be exactly 64 hex characters`                |
| Winsock init fails            | `WSAStartup failed: <error_code>`                      |
| `wintun.dll` not found        | `Failed to load wintun.dll`                            |
| Wintun functions not found    | `Failed to load Wintun functions. DLL may be corrupt`  |
| Adapter creation fails        | `Failed to create Wintun adapter. Run as Administrator` |
| Invalid server IP             | `Invalid server IP: <ip>`                              |
| Socket creation fails         | `Failed to create socket: <error_code>`                |
| Key generation fails          | `Failed to generate key pair`                          |
| Public key send fails         | `Failed to send public key: <error_code>`              |
| Server key receive timeout    | `Failed to receive server public key`                  |
| Key derivation fails          | `Key derivation failed`                                |
| PSK HMAC mismatch             | `PSK authentication FAILED! Possible MITM attack`      |
| Socket connect fails          | `Failed to connect socket: <error_code>`               |
| Wintun session start fails    | `Failed to start Wintun session` (+ route restore)     |

---

## 12. Troubleshooting

### Common Issues

| Problem                                    | Solution                                                    |
|-------------------------------------------|-------------------------------------------------------------|
| `Failed to create Wintun adapter`         | Right-click → **Run as Administrator**                      |
| `Failed to load wintun.dll`               | Ensure `wintun.dll` is in the same folder as `login.exe`    |
| Server key receive timeout                | Check server IP, ensure server is running, check firewall   |
| No internet after crash                   | Run: `route add 0.0.0.0 mask 0.0.0.0 <your_gateway> metric 1` |
| `PSK authentication FAILED`              | Ensure both client and server use the exact same PSK        |
| High CPU usage                            | Should not happen — `WaitForSingleObject` prevents busy-wait |

### Manual Route Recovery

If the VPN crashes without cleanup, restore internet manually:

```bash
# Replace 192.168.1.1 with YOUR actual gateway IP
route delete 0.0.0.0
route add 0.0.0.0 mask 0.0.0.0 192.168.1.1 metric 1
```

---

## 13. Limitations & Future Work

### Current Limitations

| Limitation                        | Impact                                               |
|----------------------------------|------------------------------------------------------|
| No replay protection window      | Captured packets could theoretically be replayed     |
| Single-threaded sender           | May bottleneck on very high throughput               |
| No reconnection logic            | If the server goes down, the client hangs            |
| No DNS leak protection           | DNS queries may bypass the tunnel                    |
| No IPv6 support                  | Only IPv4 traffic is tunneled                        |
| Server code not included         | Only the client-side is implemented in this project  |

### Potential Improvements

- **Anti-replay window** — Add a sliding window with sequence numbers (like IPsec)
- **Auto-reconnect** — Detect server disconnection and re-establish the tunnel
- **DNS leak prevention** — Force DNS through the tunnel or use a DNS-over-HTTPS resolver
- **Config file support** — Load settings from a `.conf` file instead of CLI args
- **IPv6 support** — Extend routing and adapter setup for dual-stack
- **GUI** — Add a simple Windows UI for connection management
- **Kill switch** — Block all non-VPN traffic via Windows Firewall rules if the tunnel drops
- **Key rotation** — Periodically renegotiate encryption keys for long sessions

---

*Document generated for VPN Client Project — Last updated: May 2026*
