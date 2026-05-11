#include <iostream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <vector>
#include <thread>
#include <atomic>
#include <openssl/core_names.h>
#include <cstdint>
#include <netioapi.h>
#include <iphlpapi.h>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

using namespace std;

static atomic<bool> g_running(true);
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

    vector<unsigned char> out;
    out.reserve(12 + outlen + final_len + 16);
    out.insert(out.end(), iv, iv + 12);
    out.insert(out.end(), cipher.begin(), cipher.begin() + outlen + final_len);
    out.insert(out.end(), tag, tag + 16);
    return out;
}

vector<unsigned char> decrypt(const unsigned char* data, int len, const unsigned char* key) {
    if (len < 28) return {};

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
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);
    plain.resize(outlen + final_len);
    return plain;
}

EVP_PKEY* gen_keys() {
    return EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
}

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
    EVP_PKEY_free(peer_pub);
    return s;
}

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

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        cout << "\n[INFO] Shutting down VPN server...\n";
        g_running = false;
        if (g_sock != INVALID_SOCKET) {
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }
        WSACleanup();
        Sleep(500);
        ExitProcess(0);
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <BIND_IP> [PSK_HEX]\n";
        cerr << "  BIND_IP  : local address to bind UDP server (use 0.0.0.0 for all)\n";
        cerr << "  PSK_HEX  : optional 64-char hex pre-shared key\n";
        cerr << "Example:\n";
        cerr << "  " << argv[0] << " 0.0.0.0 012345...\n";
        return 1;
    }

    string bind_ip = argv[1];
    unsigned char psk[32];
    bool has_psk = false;

    if (argc >= 3) {
        string psk_hex = argv[2];
        if (psk_hex.length() != 64) {
            cerr << "[ERROR] PSK must be exactly 64 hex characters (32 bytes).\n";
            return 1;
        }
        for (int i = 0; i < 32; ++i) {
            psk[i] = (unsigned char)strtoul(psk_hex.substr(i * 2, 2).c_str(), NULL, 16);
        }
        has_psk = true;
        cout << "[INFO] Using provided pre-shared key for authentication.\n";
    } else {
        cout << "[WARNING] No PSK provided. Handshake will be unauthenticated.\n";
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "[ERROR] WSAStartup failed: " << WSAGetLastError() << "\n";
        return 1;
    }

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

    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(L"vpn0", L"Wintun", NULL);
    if (!adapter) {
        cerr << "[ERROR] Failed to create Wintun adapter. Run as Administrator.\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    system("netsh interface ip set address \"vpn0\" static 10.0.0.1 255.255.255.0");
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

    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == INVALID_SOCKET) {
        cerr << "[ERROR] Failed to create socket: " << WSAGetLastError() << "\n";
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(51820);
    if (inet_pton(AF_INET, bind_ip.c_str(), &bind_addr.sin_addr) != 1) {
        cerr << "[ERROR] Invalid bind IP: " << bind_ip << "\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    if (bind(g_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        cerr << "[ERROR] Failed to bind socket: " << WSAGetLastError() << "\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    cout << "[INFO] Listening for client on " << bind_ip << ":51820\n";

    unsigned char client_pub[32];
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    int recv_len = recvfrom(g_sock, (char*)client_pub, 32, 0,
                            (sockaddr*)&client_addr, &client_addr_len);
    if (recv_len != 32) {
        cerr << "[ERROR] Failed to receive client public key.\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

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

    if (sendto(g_sock, (char*)my_pub.data(), 32, 0,
               (sockaddr*)&client_addr, client_addr_len) == SOCKET_ERROR) {
        cerr << "[ERROR] Failed to send server public key: " << WSAGetLastError() << "\n";
        EVP_PKEY_free(my_pk);
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    vector<unsigned char> key = derive(my_pk, client_pub);
    EVP_PKEY_free(my_pk);
    if (key.empty()) {
        cerr << "[ERROR] Key derivation failed.\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    if (has_psk) {
        unsigned char client_hmac[32];
        recv_len = recvfrom(g_sock, (char*)client_hmac, 32, 0,
                            (sockaddr*)&client_addr, &client_addr_len);
        if (recv_len != 32) {
            cerr << "[ERROR] Failed to receive client authentication HMAC.\n";
            closesocket(g_sock);
            FreeLibrary(w_dll);
            WSACleanup();
            return 1;
        }

        vector<unsigned char> expected = compute_handshake_hmac(psk, 32, client_pub, my_pub.data());
        if (CRYPTO_memcmp(expected.data(), client_hmac, 32) != 0) {
            cerr << "[ERROR] PSK authentication FAILED!\n";
            closesocket(g_sock);
            FreeLibrary(w_dll);
            WSACleanup();
            return 1;
        }

        vector<unsigned char> server_hmac = compute_handshake_hmac(psk, 32, client_pub, my_pub.data());
        if (sendto(g_sock, (char*)server_hmac.data(), 32, 0,
                   (sockaddr*)&client_addr, client_addr_len) == SOCKET_ERROR) {
            cerr << "[ERROR] Failed to send server HMAC: " << WSAGetLastError() << "\n";
            closesocket(g_sock);
            FreeLibrary(w_dll);
            WSACleanup();
            return 1;
        }
        cout << "[INFO] PSK authentication successful.\n";
    } else {
        cout << "[WARNING] Skipping PSK authentication (no PSK provided).\n";
    }

    if (connect(g_sock, (sockaddr*)&client_addr, client_addr_len) == SOCKET_ERROR) {
        cerr << "[ERROR] Failed to connect socket to client: " << WSAGetLastError() << "\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    DWORD timeout = 1000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    WINTUN_SESSION_HANDLE sess = WintunStartSession(adapter, 0x400000);
    if (!sess) {
        cerr << "[ERROR] Failed to start Wintun session.\n";
        closesocket(g_sock);
        FreeLibrary(w_dll);
        WSACleanup();
        return 1;
    }

    cout << "[INFO] VPN tunnel established with client. Press Ctrl+C to stop.\n";

    thread rx([&]() {
        unsigned char buf[2048];
        while (g_running) {
            int r = recv(g_sock, (char*)buf, sizeof(buf), 0);
            if (r > 0) {
                vector<unsigned char> p = decrypt(buf, r, key.data());
                if (!p.empty()) {
                    unsigned char* wp = WintunAllocateSendPacket(sess, (uint32_t)p.size());
                    if (wp) {
                        memcpy(wp, p.data(), p.size());
                        WintunSendPacket(sess, wp);
                    }
                }
            }
        }
    });
    rx.detach();

    while (g_running) {
        uint32_t p_size = 0;
        unsigned char* pkt = WintunReceivePacket(sess, &p_size);
        if (pkt) {
            unsigned char iv[12];
            RAND_bytes(iv, 12);
            vector<unsigned char> enc = encrypt(pkt, p_size, key.data(), iv);
            if (!enc.empty()) {
                send(g_sock, (char*)enc.data(), (int)enc.size(), 0);
            }
            WintunReleaseReceivePacket(sess, pkt);
        } else {
            WaitForSingleObject(WintunGetReadWaitEvent(sess), 1000);
        }
    }

    closesocket(g_sock);
    FreeLibrary(w_dll);
    WSACleanup();
    return 0;
}
