Run these commands as administrator in Power Shell in separate terminals:

# Compile server
g++ -std=c++17 vpn_server.cpp -o vpn_server.exe -I"C:\msys64\ucrt64\include" -L"C:\msys64\ucrt64\lib" -lws2_32 -lIphlpapi -lcrypto -static

# Compile client
g++ -std=c++17 vpn_client.cpp -o vpn_client.exe -I"C:\msys64\ucrt64\include" -L"C:\msys64\ucrt64\lib" -lws2_32 -lIphlpapi -lcrypto -static

./vpn_server.exe 0.0.0.0
./vpn_client.exe 127.0.0.1 192.168.1.1