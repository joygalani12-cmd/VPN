#include <iostream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <thread>
#include <openssl/core_names.h>
#include <cstdint>
#include <netioapi.h>
#include <iphlpapi.h>

#pragma comment(lib, "Iphlpapi.lib")

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")

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
    vector<unsigned char> cipher(len);
    unsigned char tag[16];
    int outlen, final_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher.data(), &outlen, plain, len);
    EVP_EncryptFinal_ex(ctx, cipher.data() + outlen, &final_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    vector<unsigned char> out;
    out.insert(out.end(), iv, iv + 12);
    out.insert(out.end(), cipher.begin(), cipher.end());
    out.insert(out.end(), tag, tag + 16);
    return out;
}

vector<unsigned char> decrypt(const unsigned char* data, int len, const unsigned char* key) {
    if (len < 28) return {}; // Too small (IV + Tag)
    
    const unsigned char* iv = data;
    const unsigned char* cipher = data + 12;
    int cipher_len = len - 28;
    const unsigned char* tag = data + 12 + cipher_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plain(cipher_len);
    int outlen;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plain.data(), &outlen, cipher, cipher_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    
    if (EVP_DecryptFinal_ex(ctx, plain.data() + outlen, &outlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // Auth Failed
    }
    EVP_CIPHER_CTX_free(ctx);
    return plain;
}

// --- Key Exchange Helpers ---
EVP_PKEY* gen_keys() { return EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); }

vector<unsigned char> get_pub(EVP_PKEY* pk) {
    size_t len = 32;
    vector<unsigned char> b(32);
    EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, b.data(), 32, &len);
    return b;
}

vector<unsigned char> derive(EVP_PKEY* priv, const unsigned char* pub_bytes) {
    EVP_PKEY* peer_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_bytes, 32);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pub);
    size_t len = 32;
    vector<unsigned char> s(32);
    EVP_PKEY_derive(ctx, s.data(), &len);
    EVP_PKEY_CTX_free(ctx);
    return s;
}

DWORD GetWintunIndex() {
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    // Get the required buffer size
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &outBufLen);
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);

    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // Check if "Wintun" is in the description
            if (wcsstr(pCurrAddresses->Description, L"Wintun") != NULL) {
                DWORD index = pCurrAddresses->IfIndex;
                free(pAddresses);
                return index;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    if (pAddresses) free(pAddresses);
    return 0;
}


int main() {

    // 1. Initial Config
    string SERVER_IP = "1.2.3.4";     // Change to your server
    string GATEWAY_IP = "10.196.63.250"; // Change to your WiFi Router IP
    
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    HMODULE w_dll = LoadLibraryA("wintun.dll");
    auto WintunCreateAdapter = (WintunCreateAdapter_t)GetProcAddress(w_dll, "WintunCreateAdapter");
    auto WintunStartSession = (WintunStartSession_t)GetProcAddress(w_dll, "WintunStartSession");
    auto WintunReceivePacket = (WintunReceivePacket_t)GetProcAddress(w_dll, "WintunReceivePacket");
    auto WintunReleaseReceivePacket = (WintunReleaseReceivePacket_t)GetProcAddress(w_dll, "WintunReleaseReceivePacket");
    auto WintunGetReadWaitEvent = (WintunGetReadWaitEvent_t)GetProcAddress(w_dll, "WintunGetReadWaitEvent");
    auto WintunAllocateSendPacket = (WintunAllocateSendPacket_t)GetProcAddress(w_dll, "WintunAllocateSendPacket");
    auto WintunSendPacket = (WintunSendPacket_t)GetProcAddress(w_dll, "WintunSendPacket");

    // 2. Setup Interface
    WINTUN_ADAPTER_HANDLE adapter = WintunCreateAdapter(L"vpn0", L"Wintun", NULL);
    system("netsh interface ip set address \"vpn0\" static 10.0.0.2 255.255.255.0");
    system("netsh interface ipv4 set subinterface \"vpn0\" mtu=1400 store=active");
    // 2. Get the index dynamically
    DWORD vpnIdx = GetWintunIndex();

    if (vpnIdx > 0) {
    cout << "Detected VPN Index: " << vpnIdx << endl;
    
    // 1. Clear any old, stuck routes first
    system("route delete 10.0.0.0 mask 255.255.255.0 > nul 2>&1");

    // 2. Use the Index (vpnIdx) instead of the Name string
    // This avoids the "syntax is incorrect" error caused by the '#' character
    std::string routeCmd = "route add 10.0.0.0 mask 255.255.255.0 0.0.0.0 IF " + std::to_string(vpnIdx) + " metric 1";
    
    if (system(routeCmd.c_str()) == 0) {
        cout << "Route successfully added to Interface " << vpnIdx << endl;
    }
}

    // 3. Handshake


    // 3. Handshake
    sockaddr_in server_addr; // Renamed from s_addr to avoid conflict
    memset(&server_addr, 0, sizeof(server_addr)); // Clear memory
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(51820);
    inet_pton(AF_INET, SERVER_IP.c_str(), &server_addr.sin_addr);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    EVP_PKEY* my_pk = gen_keys();
    vector<unsigned char> my_pub = get_pub(my_pk);

    // Use the new variable name here
    sendto(sock, (char*)my_pub.data(), 32, 0, (sockaddr*)&server_addr, sizeof(server_addr));

    unsigned char srv_pub[32];
    int slen = sizeof(server_addr);
    recvfrom(sock, (char*)srv_pub, 32, 0, (sockaddr*)&server_addr, &slen);
    vector<unsigned char> key = derive(my_pk, srv_pub);

    // 4. Routing (Fixing the loop)
    string bypass = "route add " + SERVER_IP + " mask 255.255.255.255 " + GATEWAY_IP + " metric 1";
    system(bypass.c_str());
    system("route delete 0.0.0.0");
    system("route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 5");

    WINTUN_SESSION_HANDLE sess = WintunStartSession(adapter, 0x400000);
    cout << "Tunnel Secure. Logic Active.\n";

    // 5. RECEIVER THREAD (Server -> Wintun)
    thread rx([&]() {
        unsigned char buf[2048];
        while (true) {
            int r = recv(sock, (char*)buf, 2048, 0);
            if (r > 0) {
                vector<unsigned char> p = decrypt(buf, r, key.data());
                if (!p.empty()) {
                    unsigned char* wp = WintunAllocateSendPacket(sess, p.size());
                    if (wp) {
                        memcpy(wp, p.data(), p.size());
                        WintunSendPacket(sess, wp);
                    }
                }
            }
        }
    });

    // 6. SENDER LOOP (Wintun -> Server)
    while (true) {
        uint32_t p_size = 0;
        unsigned char* pkt = WintunReceivePacket(sess, &p_size);

        if (pkt) {
            // 1. Generate unique IV for this packet
            unsigned char iv[12]; 
            RAND_bytes(iv, 12);

            // 2. Encrypt the Wintun packet
            vector<unsigned char> enc = encrypt(pkt, p_size, key.data(), iv);

            // 3. Send to server
            // FIX: Changed '&sock' to '&server_addr'
            // FIX: Changed 'sizeof(s_addr)' to 'sizeof(server_addr)'
            sendto(sock, (char*)enc.data(), (int)enc.size(), 0, (sockaddr*)&server_addr, sizeof(server_addr));

            // 4. Free the Wintun buffer
            WintunReleaseReceivePacket(sess, pkt);
        } else {
            // Wait for more data to avoid 100% CPU usage
            WaitForSingleObject(WintunGetReadWaitEvent(sess), INFINITE);
        }
    }

    return 0;
}