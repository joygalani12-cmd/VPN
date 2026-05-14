#include <iostream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <vector>
#include <thread>
#include <atomic>
#include <openssl/core_names.h>
#include <cstdint>
#include <netioapi.h>
#include <iphlpapi.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

using namespace std;

// --- Global State for Cleanup ---
static atomic<bool> g_running(true);
static string g_server_ip;
static string g_gateway_ip;
static SOCKET g_sock = INVALID_SOCKET;

// --- Wintun API ---
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;
typedef WINTUN_ADAPTER_HANDLE(WINAPI* WintunCreateAdapter_t)(const WCHAR*, const WCHAR*, const GUID*);
typedef WINTUN_SESSION_HANDLE(WINAPI* WintunStartSession_t)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef unsigned char*(WINAPI* WintunReceivePacket_t)(WINTUN_SESSION_HANDLE, uint32_t*);
typedef void(WINAPI* WintunReleaseReceivePacket_t)(WINTUN_SESSION_HANDLE, const unsigned char*);
typedef HANDLE(WINAPI* WintunGetReadWaitEvent_t)(WINTUN_SESSION_HANDLE);
typedef unsigned char*(WINAPI* WintunAllocateSendPacket_t)(WINTUN_SESSION_HANDLE, uint32_t);
typedef void(WINAPI* WintunSendPacket_t)(WINTUN_SESSION_HANDLE, const unsigned char*);

// --- Crypto Functions ---

vector<unsigned char> encrypt(const unsigned char* plain, int len, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[ERROR] Failed to create cipher context.\n";
        return {};
    }

    vector<unsigned char> cipher(len);
    unsigned char tag[16];
    int outlen = 0, final_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, cipher.data(), &outlen, plain, len) != 1 ||
        EVP_EncryptFinal_ex(ctx, cipher.data() + outlen, &final_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        cerr << "[ERROR] Encryption failed.\n";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    // Format: [IV (12)] [Ciphertext] [Tag (16)]
    vector<unsigned char> out;
    out.reserve(12 + outlen + final_len + 16);
    out.insert(out.end(), iv, iv + 12);
    out.insert(out.end(), cipher.begin(), cipher.begin() + outlen + final_len);
    out.insert(out.end(), tag, tag + 16);
    return out;
}

vector<unsigned char> decrypt(const unsigned char* data, int len, const unsigned char* key) {
    if (len < 28) return {}; // Too small (12 IV + 16 Tag minimum)

    const unsigned char* iv = data;
    const unsigned char* cipher = data + 12;
    int cipher_len = len - 28;
    const unsigned char* tag = data + 12 + cipher_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "[ERROR] Failed to create decryption context.\n";
        return {};
    }

    vector<unsigned char> plain(cipher_len);
    int outlen = 0, final_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plain.data(), &outlen, cipher, cipher_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    if (EVP_DecryptFinal_ex(ctx, plain.data() + outlen, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // Auth Failed
    }
    EVP_CIPHER_CTX_free(ctx);
    plain.resize(outlen + final_len);
    return plain;
}

// --- Key Exchange Helpers ---
EVP_PKEY* gen_keys() { return EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); }

vector<unsigned char> get_pub(EVP_PKEY* pk) {
    size_t len = 32;
    vector<unsigned char> b(32);
    if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, b.data(), 32, &len) != 1) {
        cerr << "[ERROR] Failed to extract public key.\n";
        return {};
    }
    return b;
}

vector<unsigned char> derive(EVP_PKEY* priv, const unsigned char* pub_bytes) {
    EVP_PKEY* peer_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_bytes, 32);
    if (!peer_pub) {
        cerr << "[ERROR] Failed to load peer public key.\n";
        return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pub);
        cerr << "[ERROR] Failed to create derivation context.\n";
        return {};
    }

    size_t len = 32;
    vector<unsigned char> s(32);

    if (EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, peer_pub) != 1 ||
        EVP_PKEY_derive(ctx, s.data(), &len) != 1) {
        cerr << "[ERROR] Key derivation failed.\n";
        s.clear();
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pub); // FIX: Was never freed before
    return s;
}

// --- PSK Authentication ---
// Computes HMAC-SHA256 over both public keys using a pre-shared key.
// Prevents MITM: attacker can't forge the HMAC without knowing the PSK,
// and substituted keys produce a different HMAC input.
vector<unsigned char> compute_handshake_hmac(const unsigned char* psk, int psk_len,
                                             const unsigned char* client_pub,
                                             const unsigned char* server_pub) {
    unsigned char msg[64];
    memcpy(msg, client_pub, 32);
    memcpy(msg + 32, server_pub, 32);

    unsigned char hmac_out[32];
    unsigned int hmac_len = 32;
    HMAC(EVP_sha256(), psk, psk_len, msg, 64, hmac_out, &hmac_len);

    return vector<unsigned char>(hmac_out, hmac_out + hmac_len);
}

// --- Network Helper ---
DWORD GetWintunIndex() {
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &outBufLen);
    if (outBufLen == 0) return 0;

    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (!pAddresses) return 0;

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurr = pAddresses;
        while (pCurr) {
            if (wcsstr(pCurr->Description, L"Wintun") != NULL) {
                DWORD index = pCurr->IfIndex;
                free(pAddresses);
                return index;
            }
            pCurr = pCurr->Next;
        }
    }
    free(pAddresses);
    return 0;
}

// --- Cleanup / Signal Handler ---
// Restores the routing table on Ctrl+C, Ctrl+Break, or window close.
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        cout << "\n[INFO] Shutting down VPN...\n";
        g_running = false;

        // Restore routing table
        system("route delete 0.0.0.0 > nul 2>&1");
        system(("route add 0.0.0.0 mask 0.0.0.0 " + g_gateway_ip + " metric 1").c_str());
        // system(("route delete " + g_server_ip + " > nul 2>&1").c_str());

        // Close socket to unblock recv()
        if (g_sock != INVALID_SOCKET) {
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }

        WSACleanup();
        cout << "[INFO] Routes restored. VPN shut down cleanly.\n";
        Sleep(500);
        ExitProcess(0);
    }
    return TRUE;
}

// --- Main ---
int main(int argc, char* argv[]) {
    cout << "[DEBUG] Program started\n";
    MessageBoxA(NULL,
                "Reached main()",
                "DEBUG",
                MB_OK);

    printf("[DEBUG] main entered\n");
    fflush(stdout);
    // 1. Parse CLI arguments
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <SERVER_IP> <GATEWAY_IP> [PSK_HEX]\n";
        cerr << "  SERVER_IP  : IP address of the VPN server\n";
        cerr << "  GATEWAY_IP : IP address of your local router/gateway\n";
        cerr << "  PSK_HEX    : (Optional) 64-char hex pre-shared key\n";
        cerr << "\nExample:\n";
        cerr << "  " << argv[0] << " 203.0.113.5 192.168.1.1\n";
        cerr << "\nGenerate a PSK with: openssl rand -hex 32\n";
        return 1;
    }

    g_server_ip = argv[1];
    g_gateway_ip = argv[2];

    // Parse or skip PSK
    unsigned char psk[32];
    bool has_psk = false;
    if (argc >= 4) {
        string psk_hex = argv[3];
        if (psk_hex.length() != 64) {
            cerr << "[ERROR] PSK must be exactly 64 hex characters (32 bytes).\n";
            return 1;
        }
        for (int i = 0; i < 32; i++) {
            psk[i] = (unsigned char)strtoul(psk_hex.substr(i * 2, 2).c_str(), NULL, 16);
        }
        has_psk = true;
        cout << "[INFO] Using provided pre-shared key for authentication.\n";
    } else {
        cerr << "[WARNING] No PSK provided. Handshake will be UNAUTHENTICATED.\n";
        cerr << "[WARNING] This is vulnerable to MITM attacks!\n";
        memset(psk, 0, 32);
    }

    // Register cleanup handler
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 2. Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "[ERROR] WSAStartup failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    // 3. Load Wintun DLL with full validation
    HMODULE w_dll = LoadLibraryA("wintun.dll");
    if (!w_dll) {
        cerr << "[ERROR] Failed to load wintun.dll. Ensure it's in the same directory.\n";
        WSACleanup();
        return 1;
    }

    auto WintunCreateAdapter   = (WintunCreateAdapter_t)GetProcAddress(w_dll, "WintunCreateAdapter");
    auto WintunStartSession    = (WintunStartSession_t)GetProcAddress(w_dll, "WintunStartSession");
    auto WintunReceivePacket   = (WintunReceivePacket_t)GetProcAddress(w_dll, "WintunReceivePacket");
    auto WintunReleaseReceivePacket = (WintunReleaseReceivePacket_t)GetProcAddress(w_dll, "WintunReleaseReceivePacket");
    auto WintunGetReadWaitEvent = (WintunGetReadWaitEvent_t)GetProcAddress(w_dll, "WintunGetReadWaitEvent");
    auto WintunAllocateSendPacket = (WintunAllocateSendPacket_t)GetProcAddress(w_dll, "WintunAllocateSendPacket");
    auto WintunSendPacket      = (WintunSendPacket_t)GetProcAddress(w_dll, "WintunSendPacket");

    if (!WintunCreateAdapter || !WintunStartSession || !WintunReceivePacket ||
        !WintunReleaseReceivePacket || !WintunGetReadWaitEvent ||
        !WintunAllocateSendPacket || !WintunSendPacket) {
        cerr << "[ERROR] Failed to load Wintun functions. DLL may be corrupt.\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // 4. Create virtual adapter
    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(L"vpn0", L"Wintun", NULL);
    if (!adapter) {
        cerr << "[ERROR] Failed to create Wintun adapter. Run as Administrator.\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    system("netsh interface ip set address \"vpn0\" static 10.0.0.2 255.255.255.0");
    system("netsh interface ipv4 set subinterface \"vpn0\" mtu=1400 store=active");

    DWORD vpnIdx = GetWintunIndex();
    if (vpnIdx > 0) {
        cout << "[INFO] Detected VPN Interface Index: " << vpnIdx << endl;
        system("route delete 10.0.0.0 mask 255.255.255.0 > nul 2>&1");
        string routeCmd = "route add 10.0.0.0 mask 255.255.255.0 0.0.0.0 IF " + to_string(vpnIdx) + " metric 1";
        if (system(routeCmd.c_str()) == 0) {
            cout << "[INFO] Route added to Interface " << vpnIdx << endl;
        }
    } else {
        cerr << "[WARNING] Could not detect Wintun adapter index.\n";
    }

    // 5. Create and configure socket
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(51820);
    if (inet_pton(AF_INET, g_server_ip.c_str(), &server_addr.sin_addr) != 1) {
        cerr << "[ERROR] Invalid server IP: " << g_server_ip << "\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) {
        cerr << "[ERROR] Failed to create socket: " << WSAGetLastError() << "\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // Set 5-second timeout for handshake phase
    DWORD timeout = 5000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // 6. Key Exchange (Handshake)
    cout << "[INFO] Starting key exchange with " << g_server_ip << "...\n";

    EVP_PKEY* my_pk = gen_keys();
    if (!my_pk) {
        cerr << "[ERROR] Failed to generate key pair.\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    vector<unsigned char> my_pub = get_pub(my_pk);
    if (my_pub.empty()) {
        EVP_PKEY_free(my_pk);
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // Send our public key
    if (sendto(g_sock, (char*)my_pub.data(), 32, 0,
               (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "[ERROR] Failed to send public key: " << WSAGetLastError() << "\n";
        EVP_PKEY_free(my_pk);
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // Receive server's public key
    unsigned char srv_pub[32];
    int slen = sizeof(server_addr);
    int recv_len = recvfrom(g_sock, (char*)srv_pub, 32, 0, (sockaddr*)&server_addr, &slen);
    if (recv_len != 32) {
        cerr << "[ERROR] Failed to receive server public key (timeout or error).\n";
        EVP_PKEY_free(my_pk);
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // Derive shared secret
    vector<unsigned char> key = derive(my_pk, srv_pub);
    EVP_PKEY_free(my_pk); // FIX: Free key pair after use

    if (key.empty()) {
        cerr << "[ERROR] Key derivation failed.\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // 7. PSK Authentication (if PSK provided)
    if (has_psk) {
        vector<unsigned char> our_hmac = compute_handshake_hmac(psk, 32, my_pub.data(), srv_pub);

        // Send our HMAC to server for verification
        sendto(g_sock, (char*)our_hmac.data(), 32, 0, (sockaddr*)&server_addr, sizeof(server_addr));

        // Receive server's HMAC
        unsigned char srv_hmac[32];
        slen = sizeof(server_addr);
        recv_len = recvfrom(g_sock, (char*)srv_hmac, 32, 0, (sockaddr*)&server_addr, &slen);
        if (recv_len != 32) {
            cerr << "[ERROR] Failed to receive server authentication HMAC.\n";
            closesocket(g_sock);
            FreeLibrary(w_dll);
            WSACleanup();
            return 1;
        }

        // Verify the server computed the same HMAC (proves it knows the PSK)
        if (CRYPTO_memcmp(our_hmac.data(), srv_hmac, 32) != 0) {
            cerr << "[ERROR] PSK authentication FAILED! Possible MITM attack. Aborting.\n";
            closesocket(g_sock);
            FreeLibrary(w_dll);
            WSACleanup();
            return 1;
        }
        cout << "[INFO] PSK authentication successful.\n";
    } else {
        cout << "[WARNING] Skipping PSK authentication (no PSK provided).\n";
    }

    // Connect UDP socket so recv()/send() work properly
    if (connect(g_sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        cerr << "[ERROR] Failed to connect socket: " << WSAGetLastError() << "\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    // Set 1-second timeout for tunnel phase (allows periodic shutdown checks)
    timeout = 1000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // 8. Routing (redirect server traffic to bypass route, keep normal Internet for now)
    // string bypass = "route add " + g_server_ip + " mask 255.255.255.255 " + g_gateway_ip + " metric 1";
    // system(bypass.c_str());
    // DISABLED for testing: default route manipulation that was breaking WiFi
    // system("route delete 0.0.0.0 mask 0.0.0.0 > nul 2>&1");
    // string defaultRoute = "netsh interface ipv4 add route prefix=0.0.0.0/0 interface=" + to_string(vpnIdx) + " nextHop=10.0.0.1 metric=5";
    // if (system(defaultRoute.c_str()) != 0) { cerr << "[WARNING] Default route addition failed.\n"; }

    // 9. Start Wintun session
    WINTUN_SESSION_HANDLE sess = WintunStartSession(adapter, 0x400000);
    if (!sess) {
        cerr << "[ERROR] Failed to start Wintun session.\n";
        // Restore routes before exiting
        system("route delete 0.0.0.0 > nul 2>&1");
        system(("route add 0.0.0.0 mask 0.0.0.0 " + g_gateway_ip + " metric 1").c_str());
        system(("route delete " + g_server_ip + " > nul 2>&1").c_str());
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    cout << "[INFO] Tunnel Secure. VPN Active. Press Ctrl+C to disconnect.\n";

    // 10. RECEIVER THREAD (Server -> Wintun)
    thread rx([&]() {
        uint64_t packets_recv = 0, bytes_recv = 0;
        unsigned char buf[2048];
        while (g_running) {
            int r = recv(g_sock, (char*)buf, 2048, 0); // FIX: recv() works after connect()
            if (r > 0) {
                vector<unsigned char> p = decrypt(buf, r, key.data());
                if (!p.empty()) {
                    unsigned char* wp = WintunAllocateSendPacket(sess, (uint32_t)p.size());
                    if (wp) {
                        memcpy(wp, p.data(), p.size());
                        WintunSendPacket(sess, wp);
                        packets_recv++;
                        bytes_recv += p.size();
                        if (packets_recv % 100 == 0) {
                            cout << "[TUNNEL] Received " << packets_recv << " packets (" << bytes_recv << " bytes decrypted)\n";
                        }
                    }
                }
            }
            // On timeout or error, loop re-checks g_running
        }
    });

    // 11. SENDER LOOP (Wintun -> Server)
    uint64_t packets_sent = 0, bytes_sent = 0;
    while (g_running) {
        uint32_t p_size = 0;
        unsigned char* pkt = WintunReceivePacket(sess, &p_size);

        if (pkt) {
            unsigned char iv[12];
            RAND_bytes(iv, 12);

            vector<unsigned char> enc = encrypt(pkt, p_size, key.data(), iv);

            if (!enc.empty()) {
                send(g_sock, (char*)enc.data(), (int)enc.size(), 0); // FIX: send() after connect()
                packets_sent++;
                bytes_sent += enc.size();
                if (packets_sent % 100 == 0) {
                    cout << "[TUNNEL] Sent " << packets_sent << " packets (" << bytes_sent << " bytes encrypted)\n";
                }
            }

            WintunReleaseReceivePacket(sess, pkt);
        } else {
            // Wait with timeout so we can check g_running periodically
            WaitForSingleObject(WintunGetReadWaitEvent(sess), 1000);
        }
    }

    if (rx.joinable()) {
        rx.join();
    }

    // Cleanup (reached if g_running set to false without signal handler exit)
    closesocket(g_sock);
    FreeLibrary(w_dll);
    WSACleanup();

    return 0;
}