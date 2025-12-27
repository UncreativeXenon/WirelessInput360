#include <SDL3/SDL.h>
#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>

// Windows Specific Networking and Crypto (for WebSocket Handshake)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#pragma comment(lib, "SDL3.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#else
// Note: This code heavily relies on WinAPI for the handshake hash. 
// For Linux/Mac, you'd need OpenSSL or a custom SHA1 implementation.
#error "This specific WebSocket implementation is designed for Windows."
#endif

// --- CONFIGURATION ---
const int MAX_PLAYERS = 4;

// --- GLOBAL SERVER STATE ---
SOCKET serverSocket = INVALID_SOCKET;
SOCKET clientSocket = INVALID_SOCKET;
std::mutex clientMutex;
std::atomic<bool> serverRunning(true);

struct PlayerSlot {
    bool active = false;
    SDL_JoystickID instance_id = 0;
    SDL_Gamepad* gamepad = nullptr;
};

PlayerSlot players[MAX_PLAYERS];

// --- NEW FUNCTION: READ PORT FROM FILE ---
int ReadPortFromFile() {
    std::ifstream portFile("port.txt");
    int port = 3000; // Default port

    if (portFile.is_open()) {
        if (!(portFile >> port)) {
            std::cerr << "[WS] Warning: Could not read integer from 'port.txt'. Using default port " << 3000 << std::endl;
            port = 3000;
        }
        else {
            // Basic validation
            if (port < 1024 || port > 65535) {
                std::cerr << "[WS] Warning: Port (" << port << ") read from file is out of common range. Using default 3000." << std::endl;
                port = 3000;
            }
            else {
                std::cout << "[WS] Using port: " << port << " (read from port.txt)" << std::endl;
            }
        }
        portFile.close();
    }
    else {
        std::cerr << "[WS] Warning: 'port.txt' not found. Using default port " << 3000 << std::endl;
    }
    return port;
}

// --- HELPER: WEBSOCKET HANDSHAKE ---
// WebSockets require a specific response to the "Sec-WebSocket-Key" header.
// We must take the key, append a magic string, SHA1 hash it, and Base64 encode it.
std::string ComputeWebSocketAcceptKey(const std::string& clientKey) {
    const char* magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = clientKey + magicGUID;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 20;
    BYTE hash[20];
    std::string result = "";

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)combined.c_str(), (DWORD)combined.length(), 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    // Hash computed, now Base64 encode it
                    DWORD b64Len = 0;
                    CryptBinaryToStringA(hash, hashLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
                    std::vector<char> b64Buf(b64Len);
                    CryptBinaryToStringA(hash, hashLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Buf.data(), &b64Len);
                    result = std::string(b64Buf.data());
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

// --- HELPER: SEND FRAME ---
void SendWebSocketMessage(const std::string& msg) {
    std::lock_guard<std::mutex> lock(clientMutex);
    if (clientSocket == INVALID_SOCKET) return;

    // Construct WebSocket Frame (Server to Client does not need masking)
    // Byte 0: 1000 0001 (Fin + Text Opcode = 0x81)
    // Byte 1: Payload Length (assuming < 125 bytes for this app)
    std::vector<uint8_t> frame;
    frame.push_back(0x81);
    frame.push_back((uint8_t)msg.length());

    // Copy payload
    frame.insert(frame.end(), msg.begin(), msg.end());

    int sent = send(clientSocket, (const char*)frame.data(), (int)frame.size(), 0);
    if (sent == SOCKET_ERROR) {
        std::cerr << "[WS] Send failed. Closing connection." << std::endl;
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
}

void ApplyVibrationCommand(const std::string& msg) {
    // Expected Format: "V:0:65535:65535"
    if (msg.empty() || msg[0] != 'V') return;

    try {
        std::stringstream ss(msg.substr(2)); // Skip "V:"
        std::string segment;
        std::vector<int> values;

        while (std::getline(ss, segment, ':')) {
            values.push_back(std::stoi(segment));
        }

        if (values.size() == 3) {
            int pIdx = values[0];
            int lowFreq = values[1];  // Left Motor (Heavy)
            int highFreq = values[2]; // Right Motor (Light)

            // Safety check
            if (pIdx >= 0 && pIdx < MAX_PLAYERS && players[pIdx].active) {
                // The client should send updates frequently to keep it going or send 0 to stop.
                SDL_RumbleGamepad(players[pIdx].gamepad,
                    (Uint16)lowFreq,
                    (Uint16)highFreq,
                    200);
                // std::cout << "Rumble Set: P" << pIdx << " L:" << lowFreq << " R:" << highFreq << std::endl;
            }
        }
    }
    catch (...) {
        std::cerr << "[WS] Invalid Rumble Command: " << msg << std::endl;
    }
}

// --- SERVER THREAD ---
void WebSocketServerThread() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) return;

    int SERVER_PORT = ReadPortFromFile();

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(SERVER_PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "[WS] Bind failed on port " << SERVER_PORT << std::endl;
        return;
    }

    if (listen(serverSocket, 1) == SOCKET_ERROR) {
        std::cerr << "[WS] Listen failed." << std::endl;
        return;
    }

    std::cout << "[WS] Server started on port " << SERVER_PORT << ". Waiting for client..." << std::endl;

    while (serverRunning) {
        // Accept a client
        SOCKET client = accept(serverSocket, NULL, NULL);
        if (client == INVALID_SOCKET) {
            if (serverRunning) std::cerr << "[WS] Accept failed." << std::endl;
            continue; // Try again
        }

        std::cout << "[WS] Client connected! Performing Handshake..." << std::endl;

        // 1. Read HTTP Handshake Request
        char buffer[2048];
        int bytesReceived = recv(client, buffer, 2048, 0);
        if (bytesReceived > 0) {
            std::string request(buffer, bytesReceived);

            // 2. Find Sec-WebSocket-Key
            std::string keyHeader = "Sec-WebSocket-Key: ";
            size_t keyPos = request.find(keyHeader);
            if (keyPos != std::string::npos) {
                size_t endPos = request.find("\r\n", keyPos);
                std::string clientKey = request.substr(keyPos + keyHeader.length(), endPos - (keyPos + keyHeader.length()));

                // 3. Generate Response Key
                std::string acceptKey = ComputeWebSocketAcceptKey(clientKey);

                // 4. Send Handshake Response
                std::ostringstream response;
                response << "HTTP/1.1 101 Switching Protocols\r\n"
                    << "Upgrade: websocket\r\n"
                    << "Connection: Upgrade\r\n"
                    << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";

                std::string resStr = response.str();
                send(client, resStr.c_str(), (int)resStr.length(), 0);

                // 5. Set Global Socket
                {
                    std::lock_guard<std::mutex> lock(clientMutex);
                    clientSocket = client;
                }
                std::cout << "[WS] Handshake complete. Connection established." << std::endl;

                // 6. Monitor connection (Simple blocking read until disconnect)
                // We don't really need to read anything for this app, but recv will return 0 or -1 on disconnect
                while (true) {
                    int bytesRead = recv(client, buffer, 2048, 0);
                    if (bytesRead <= 0) {
                        std::cout << "[WS] Client disconnected." << std::endl;
                        break;
                    }

                    if (bytesRead < 6) continue; // Too small to be a valid masked frame

                    uint8_t b0 = (uint8_t)buffer[0];
                    uint8_t b1 = (uint8_t)buffer[1];

                    // Check if it's a disconnect opcode (0x88)
                    if ((b0 & 0x0F) == 0x08) {
                        std::cout << "[WS] Client sent close frame." << std::endl;
                        break;
                    }

                    bool isMasked = (b1 & 0x80) != 0;
                    int payloadLen = b1 & 0x7F;

                    if (payloadLen < 126 && isMasked && bytesRead >= (6 + payloadLen)) {

                        // Mask keys are at bytes 2, 3, 4, 5
                        uint8_t mask[4];
                        mask[0] = buffer[2];
                        mask[1] = buffer[3];
                        mask[2] = buffer[4];
                        mask[3] = buffer[5];

                        // Payload starts at byte 6
                        std::string decodedMsg = "";
                        for (int i = 0; i < payloadLen; ++i) {
                            // Unmask: Data XOR Mask
                            char c = buffer[6 + i] ^ mask[i % 4];
                            decodedMsg += c;
                        }

                        // Process the clean message
                        ApplyVibrationCommand(decodedMsg);
                    }
                }

                // Cleanup after disconnect
                {
                    std::lock_guard<std::mutex> lock(clientMutex);
                    closesocket(clientSocket);
                    clientSocket = INVALID_SOCKET;
                }
            }
        }
        else {
            closesocket(client);
        }
    }

    closesocket(serverSocket);
    WSACleanup();
}

// --- GAMEPAD LOGIC ---

int GetPlayerIndex(SDL_JoystickID id) {
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        if (players[i].active && players[i].instance_id == id) return i;
    }
    return -1;
}

int GetFirstFreeSlot() {
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        if (!players[i].active) return i;
    }
    return -1;
}

int GetHatState(SDL_Gamepad* pad) {
    bool u = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_DPAD_UP);
    bool d = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_DPAD_DOWN);
    bool l = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_DPAD_LEFT);
    bool r = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_DPAD_RIGHT);

    // Handle diagonals first
    if (u && r) return 1; // Up-Right
    if (d && r) return 3; // Down-Right
    if (d && l) return 5; // Down-Left
    if (u && l) return 7; // Up-Left

    // Single directions
    if (u) return 0;
    if (r) return 2;
    if (d) return 4;
    if (l) return 6;

    return 8; // Neutral
}

void PrintGamepadState(int playerIndex) {
    SDL_Gamepad* pad = players[playerIndex].gamepad;
    if (!pad) return;

    std::stringstream ss;

    // 1. Controller Number
    ss << std::setw(2) << std::setfill('0') << (playerIndex);

    // 2. Analogs
    auto addAnalog = [&](Sint16 val) {
        uint8_t out = (uint8_t)(((uint32_t)(val + 32768) * 255) / 65535);
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)out;
    };
    addAnalog(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_LEFTX));
    addAnalog(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_LEFTY));
    addAnalog(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_RIGHTX));
    addAnalog(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_RIGHTY));

    // 3. Buttons
    bool square = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_WEST);
    bool cross = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_SOUTH);
    bool circle = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_EAST);
    bool triangle = SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_NORTH);

    uint8_t face = 0;
    if (square)   face |= 0x10;  // Square
    if (cross)    face |= 0x20;  // Cross
    if (circle)   face |= 0x40;  // Circle
    if (triangle) face |= 0x80;  // Triangle

    uint8_t hat = GetHatState(pad) & 0x0F; // D-pad in low nibble
    uint8_t packetByte5 = hat | face;      // combined byte

    ss << std::hex << std::setw(2) << std::setfill('0') << (int)packetByte5;

    uint8_t byte6 = 0;
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_LEFT_SHOULDER))  byte6 |= 0x01; // L1
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER)) byte6 |= 0x02; // R1
    if (SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_LEFT_TRIGGER) > 1000) byte6 |= 0x04; // L2 digital
    if (SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_RIGHT_TRIGGER) > 1000)  byte6 |= 0x08; // R2 digital
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_BACK))          byte6 |= 0x10; // Share / Back
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_START))         byte6 |= 0x20; // Options / Start
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_LEFT_STICK))    byte6 |= 0x40; // L3
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_RIGHT_STICK))   byte6 |= 0x80; // R3

    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte6;

    // 4. Home/Touchpad
    uint8_t byte7 = 0;

    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_GUIDE)) byte7 |= 0x01; // PS button
    if (SDL_GetGamepadButton(pad, SDL_GAMEPAD_BUTTON_TOUCHPAD)) byte7 |= 0x02; // Touchpad click

    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte7;

    // 5. Triggers
    auto addTrigger = [&](Sint16 val) {
        uint8_t out = (uint8_t)(uint32_t)(val / 128);
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)out;
    };
    addTrigger(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_LEFT_TRIGGER));
    addTrigger(SDL_GetGamepadAxis(pad, SDL_GAMEPAD_AXIS_RIGHT_TRIGGER));

    std::string output = ss.str();

    // Print to Console
    //std::cout << output << std::endl;

    // Send to WebSocket
    SendWebSocketMessage(output);
}

void HandleGamepadEvent(const SDL_Event& event) {
    const SDL_JoystickID which = event.gdevice.which;

    // --- CONNECT ---
    if (event.type == SDL_EVENT_GAMEPAD_ADDED) {
        int existingIndex = GetPlayerIndex(which);
        if (existingIndex != -1) return;

        int slot = GetFirstFreeSlot();
        if (slot != -1) {
            SDL_Gamepad* newGamepad = SDL_OpenGamepad(which);
            if (newGamepad) {
                std::cout << "Gamepad " << slot << " Added\n";
                players[slot].active = true;
                players[slot].instance_id = which;
                players[slot].gamepad = newGamepad;
                // We don't need to print here immediately, the main loop will pick it up in <16ms
            }
        }
        return;
    }

    // --- DISCONNECT ---
    if (event.type == SDL_EVENT_GAMEPAD_REMOVED) {
        int slot = GetPlayerIndex(which);
        if (slot != -1) {
            SDL_CloseGamepad(players[slot].gamepad);
            std::cout << "Gamepad " << slot << " Removed\n";
            players[slot].active = false;
            players[slot].gamepad = nullptr;
            players[slot].instance_id = 0;

            // Send one final "neutral/disconnected" packet
            std::stringstream ss;
            ss << "1" << slot << "80807f7f0800000000";
            std::string output = ss.str();
            std::cout << "[Disconnect] " << output << std::endl;
            SendWebSocketMessage(output);
            SendWebSocketMessage(output);
            SendWebSocketMessage(output);
        }
        return;
    }

    // Note: We removed the Button/Axis checks here. 
    // We will poll the state directly in main().
}

int main(int argc, char* argv[]) {
    // 1. Initialize SDL
    if (!SDL_Init(SDL_INIT_GAMEPAD | SDL_INIT_EVENTS)) {
        std::cerr << "Initialization Error: " << SDL_GetError() << std::endl;
        return 1;
    }

    std::cout << "=============================================" << std::endl;
    std::cout << "   SDL3 Controller -> WebSocket Server       " << std::endl;
    std::cout << "=============================================" << std::endl;

    // 2. Start WebSocket Server in Background Thread
    std::thread wsThread(WebSocketServerThread);
    wsThread.detach(); // Let it run independently

    // 3. Check Existing Controllers
    int num_joysticks = 0;
    SDL_JoystickID* joysticks = SDL_GetJoysticks(&num_joysticks);
    if (joysticks) {
        for (int i = 0; i < num_joysticks; ++i) {
            if (SDL_IsGamepad(joysticks[i])) {
                SDL_Event ev;
                ev.type = SDL_EVENT_GAMEPAD_ADDED;
                ev.gdevice.which = joysticks[i];
                HandleGamepadEvent(ev);
            }
        }
        SDL_free(joysticks);
    }

    // 4. Event Loop (POLLING MODE)
    bool running = true;
    SDL_Event event;

    // Target Tick Rate: 60 updates per second
    const int TICK_RATE_MS = 16;

    while (running) {
        // A. Process Events (Hardware changes, Quits, etc.)
        // We use PollEvent instead of WaitEvent so we don't block
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_EVENT_QUIT) {
                running = false;
            }
            // Handle Connect/Disconnect events
            HandleGamepadEvent(event);
        }

        // B. Send State for ALL Active Players
        // This happens every loop iteration, regardless of input changes
        for (int i = 0; i < MAX_PLAYERS; ++i) {
            if (players[i].active && players[i].gamepad) {
                // SDL_GetGamepadButton/Axis functions return the *current* state
                // internally, so we can just call your existing helper function.
                PrintGamepadState(i);
            }
        }

        // C. Rate Limiting
        // Without this, the loop would run at 100% CPU usage and flood the socket
        SDL_Delay(TICK_RATE_MS);
    }
}