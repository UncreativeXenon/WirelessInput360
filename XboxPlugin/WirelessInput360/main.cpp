#include <xtl.h>
#include <time.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <sstream>
#include <fstream>
#include <xkelib.h>
#include "Detours.h"
#include <winsockx.h>
#include <sys/stat.h>
#pragma comment(lib, "xnet.lib")

// internal hard disk
#define MOUNT_HDD "Hdd:"
#define DEVICE_HARDISK0_PART1 "\\Device\\Harddisk0\\Partition1"
// usb memory stick
#define MOUNT_USB "Usb:"
#define MOUNT_USB0 "Usb0:"
#define DEVICE_USB0 "\\Device\\Mass0"    
#define MOUNT_USB1 "Usb1:"
#define DEVICE_USB1 "\\Device\\Mass1"
#define MOUNT_USB2 "Usb2:"
#define DEVICE_USB2 "\\Device\\Mass2"
// internal slim trinity mu
#define MOUNT_INTMU "IntMu:"
#define DEVICE_INTMEM "\\Device\\BuiltInMuUsb\\Storage"
// CD / DVD 
#define MOUNT_DVD "Dvd:"
#define DEVICE_CDROM0 "\\Device\\Cdrom0"
// Nand Flash
#define MOUNT_FLASH "Flash:"
#define DEVICE_NAND_FLASH "\\Device\\Flash"
// DEVKIT folder on Hdd
#define MOUNT_DEVKIT "DEVKIT:"
#define DEVICE_DEVKIT "\\Device\\Harddisk0\\Partition1\\DEVKIT"
// Games folder on Hdd
#define MOUNT_HDDGAMES "HddGames:"
#define DEVICE_HDDGAMES "\\Device\\Harddisk0\\Partition1\\Games"
// Apps folder on Hdd
#define MOUNT_HDDAPPS "HddApps:"
#define DEVICE_HDDAPPS "\\Device\\Harddisk0\\Partition1\\Apps"
// Network share using connectx
#define DEVICE_NETSHARE "Netshare:"
#define DEVICE_SMB "\\Network\\Smb"
// internal corona 4g mu
#define MOUNT_MMCMU "MmcMu:"
#define DEVICE_MMCMU "\\Device\\BuiltInMuMmc\\Storage"
// big block NAND mu
#define MOUNT_FLASHMU "FlashMu:"
#define DEVICE_FLASHMU "\\Device\\BuiltInMuSfc"
// memory unit
#define MOUNT_MU "Mu:"
#define DEVICE_MEMORY_UNIT0 "\\Device\\Mu0"
#define MOUNT_MU1 "Mu1:"
#define DEVICE_MEMORY_UNIT1 "\\Device\\Mu1"    
// USB memory unit
#define MOUNT_USBMU0 "UsbMu0:"
#define DEVICE_USBMU0 "\\Device\\Mass0PartitionFile\\Storage"
#define MOUNT_USBMU1 "UsbMu1:"
#define DEVICE_USBMU1 "\\Device\\Mass1PartitionFile\\Storage"
#define MOUNT_USBMU2 "UsbMu2:"
#define DEVICE_USBMU2 "\\Device\\Mass2PartitionFile\\Storage"

PLDR_DATA_TABLE_ENTRY pDataTable = nullptr;
char pluginPath[MAX_PATH];
char ip[64] = "192.168.1.1";
int port = 3000;
bool gotIp = false;

Detour XamInputGetStateDetour;
Detour XamInputGetCapabilitiesDetour;
Detour XamInactivityDetectRecentActivityDetour;
Detour XamInputSetStateDetour;

// Global Socket for the hook to access
SOCKET g_ServerSocket = INVALID_SOCKET;

// Cache to prevent sending duplicate packets (spam reduction)
XINPUT_VIBRATION g_LastVibration[4] = { {0,0}, {0,0}, {0,0}, {0,0} };

uint16_t swap_endianness_16(uint16_t val) {
	return (val >> 8) | (val << 8);
}

BOOL IsTrayOpen() {
	BYTE Input[0x10] = { 0 }, Output[0x10] = { 0 };
	Input[0] = 0xA;
	HalSendSMCMessage(Input, Output);
	return (Output[1] == 0x60);
}

enum ControllerStatus {
	INACTIVE,
	ACTIVE,
};

#pragma pack(push, 1)
struct Report {
	uint8_t reportId;
};

struct ButtonsReport : Report {
	uint8_t x;
	uint8_t y;
	uint8_t z;
	uint8_t rz;
	uint8_t triangle : 1;
	uint8_t circle : 1;
	uint8_t cross : 1;
	uint8_t square : 1;
	uint8_t hat_switch : 4;
	uint8_t r3 : 1;
	uint8_t l3 : 1;
	uint8_t options : 1;
	uint8_t share : 1;
	uint8_t r2 : 1;
	uint8_t l2 : 1;
	uint8_t r1 : 1;
	uint8_t l1 : 1;
	uint8_t : 6;
	uint8_t touchpad : 1;
	uint8_t ps : 1;
	uint8_t rx;
	uint8_t ry;
	uint8_t vendor_defined;
};
#pragma pack(pop)

typedef struct _XINPUT_VIBRATIONEX
{
	WORD                                wLeftMotorSpeed;
	WORD                                wRightMotorSpeed;
} XINPUT_VIBRATION_EX, *PXINPUT_VIBRATION_EX;

typedef struct _XINPUT_CAPABILITIESEX
{
	BYTE                                Type;
	BYTE                                SubType;
	WORD                                Flags;
	XINPUT_GAMEPAD                      Gamepad;
	XINPUT_VIBRATION                    Vibration;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
} XINPUT_CAPABILITIES_EX, *PXINPUT_CAPABILITIES_EX;

typedef int(*xam_user_bind_device_callback_func_t)(unsigned int controllerId, unsigned int context, unsigned __int8 category, bool disconnect, unsigned __int8* userIndex);
typedef void(*mm_free_physical_memory_func_t)(DWORD type, DWORD address);

xam_user_bind_device_callback_func_t XamUserBindDeviceCallback = nullptr;
mm_free_physical_memory_func_t MmFreePhysicalMemory = nullptr;

DWORD* XampInputRoutedToSysapp = nullptr;

struct Controller {
	ButtonsReport currentState;
	uint8_t userIndex;
	uint32_t packetNumber;
	ControllerStatus ControllerStatus;

	Controller()
		: ControllerStatus(INACTIVE)
	{
	}
} __declspec(align(4));

volatile int g_ClientThreadRunning = 1;

Controller connectedControllers[4];

void RemoveDevice(int controllerIndex) {
	connectedControllers[controllerIndex].ControllerStatus = INACTIVE;
	XamUserBindDeviceCallback(0xa7553952 + controllerIndex, 0x0000000010000005 + controllerIndex, 0, true, 0);
}

void AddDevice(int controllerIndex) {
	Controller c = Controller();
	c.ControllerStatus = ACTIVE;
	c.packetNumber = 0;

	uint8_t userIndex = -1;
	XamUserBindDeviceCallback(0xa7553952 + controllerIndex, 0x0000000010000005 + controllerIndex, 0, false, &userIndex);
	c.userIndex = userIndex;

	connectedControllers[controllerIndex] = c;
}

int16_t ConvertToFullRange(uint8_t input, bool invert_y = false) {
	if (!invert_y)
		return static_cast<int16_t>((input - 128) * 256);
	else
		return static_cast<int16_t>((~(input)-128) * 256);
}

DWORD XamInputGetStateHook(DWORD user, DWORD flags, XINPUT_STATE* input_state) {
	DWORD status = XamInputGetStateDetour.GetOriginal<decltype(&XamInputGetStateHook)>()(user, flags, input_state);

	if ((user & 0xFF) == 0xFF)
		user = 0;

	if (!input_state)
		return status;

	static DWORD lastPressTime = 0;
	static const DWORD cooldownDuration = 1000;

	if (status == ERROR_DEVICE_NOT_CONNECTED) {
		ButtonsReport b;
		Controller* c = nullptr;
		for (int i = 0; i < (sizeof(connectedControllers) / sizeof(Controller)); i++) {
			if (connectedControllers[i].ControllerStatus == ACTIVE) {
				if (connectedControllers[i].userIndex == user) {
					c = &connectedControllers[i];
					b = connectedControllers[i].currentState;
					break;
				}
			}
		}

		if (!c)
			return status;

		// HUD is open.
		if (XampInputRoutedToSysapp[c->userIndex]) {
			// 0x1 is used for titles, 0x0 is used by some offhosts and debug input.
			if ((flags == 0x1) || (flags == 0x0)) {
				return ERROR_SUCCESS;
			}
		}

		if (b.ps) {
			DWORD now = GetTickCount();
			if (now - lastPressTime >= cooldownDuration) {
				lastPressTime = now;
				XamInputSendXenonButtonPress(user);
			}
		}

		if (b.cross)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_A;

		if (b.circle)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_B;

		if (b.triangle)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_Y;

		if (b.square)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_X;

		if (b.options)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_START;

		if (b.share)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_BACK;

		if (b.r3)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_RIGHT_THUMB;

		if (b.l3)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_LEFT_THUMB;

		if (b.r1)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;

		if (b.l1)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_LEFT_SHOULDER;

		if (b.hat_switch == 0)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_UP;

		if (b.hat_switch == 2)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_RIGHT;

		if (b.hat_switch == 4)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_DOWN;

		if (b.hat_switch == 6)
			input_state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_LEFT;

		input_state->Gamepad.sThumbRX = ConvertToFullRange(b.z);
		input_state->Gamepad.sThumbRY = ConvertToFullRange(b.rz, true);

		input_state->Gamepad.sThumbLX = ConvertToFullRange(b.x);
		input_state->Gamepad.sThumbLY = ConvertToFullRange(b.y, true);

		input_state->Gamepad.bRightTrigger = b.ry;
		input_state->Gamepad.bLeftTrigger = b.rx;
		input_state->dwPacketNumber = ++c->packetNumber;

		return ERROR_SUCCESS;
	}
	return status;
}

DWORD XamInputGetCapabilitiesExHook(DWORD unk, DWORD user, DWORD flags, XINPUT_CAPABILITIES_EX* capabilities) {
	DWORD status = XamInputGetCapabilitiesDetour.GetOriginal<decltype(&XamInputGetCapabilitiesExHook)>()(unk, user, flags, capabilities);

	if ((user & 0xFF) == 0xFF)
		user = 0;

	if (!capabilities)
		return status;

	if (status == ERROR_DEVICE_NOT_CONNECTED) {
		Controller* c = nullptr;
		for (int i = 0; i < (sizeof(connectedControllers) / sizeof(Controller)); i++) {
			if (connectedControllers[i].ControllerStatus == ACTIVE) {
				if (connectedControllers[i].userIndex == user) {
					c = &connectedControllers[i];
					break;
				}
			}
		}

		if (!c)
			return status;

		capabilities->Type = XINPUT_DEVTYPE_GAMEPAD;
		capabilities->SubType = XINPUT_DEVSUBTYPE_GAMEPAD;
		capabilities->Flags = 0;

		XINPUT_STATE state;
		memset(&state, 0, sizeof(XINPUT_STATE));
		XamInputGetStateHook(user, 0, &state);
		capabilities->Gamepad = state.Gamepad;
		capabilities->Vibration.wLeftMotorSpeed = 0;
		capabilities->Vibration.wRightMotorSpeed = 0;
		return ERROR_SUCCESS;
	}
}

void SendVibrationUpdate(int userIndex, unsigned short left, unsigned short right) {
	if (g_ServerSocket == INVALID_SOCKET) return;

	// OPTIMIZATION: Only send if the values changed
	if (g_LastVibration[userIndex].wLeftMotorSpeed == left &&
		g_LastVibration[userIndex].wRightMotorSpeed == right) {
		return;
	}

	// Update the cache
	g_LastVibration[userIndex].wLeftMotorSpeed = left;
	g_LastVibration[userIndex].wRightMotorSpeed = right;

	// 1. Format the message: "V:Index:Left:Right"
	char msgBuf[64];
	sprintf(msgBuf, "V:%d:%d:%d", userIndex, left, right);
	std::string msg = msgBuf;

	// 2. Build the WebSocket Frame (Masked)
	std::vector<uint8_t> frame;
	frame.push_back(0x81); // Byte 0: FIN + Text Opcode

	// Byte 1: Mask Bit (0x80) + Payload Length
	// (Assuming payload is short, < 126 bytes, which it is for this string)
	frame.push_back(0x80 | (uint8_t)msg.length());

	// Bytes 2-5: Generate Random Mask Key
	uint8_t mask[4];
	for (int i = 0; i < 4; i++) mask[i] = (uint8_t)(rand() % 0xFF);

	frame.push_back(mask[0]);
	frame.push_back(mask[1]);
	frame.push_back(mask[2]);
	frame.push_back(mask[3]);

	// Bytes 6+: Payload (XOR Encrypted with Mask)
	for (size_t i = 0; i < msg.length(); ++i) {
		frame.push_back(msg[i] ^ mask[i % 4]);
	}

	// 3. Send using NetDll
	NetDll_send(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP),
		g_ServerSocket,
		(const char*)frame.data(),
		frame.size(),
		0);
}

DWORD XamInputSetStateHook(DWORD user, DWORD flags, PXINPUT_VIBRATION pVibration, BYTE bAmplitude, BYTE bFrequency, BYTE bOffset) {
    // Call the original first so the actual controller vibrates locally
    DWORD status = XamInputSetStateDetour.GetOriginal<decltype(&XamInputSetStateHook)>()(user, flags, pVibration, bAmplitude, bFrequency, bOffset);

	if ((user & 0xFF) == 0xFF)
		user = 0;

	if (status == ERROR_DEVICE_NOT_CONNECTED) {
		ButtonsReport b;
		Controller* c = nullptr;
		for (int i = 0; i < (sizeof(connectedControllers) / sizeof(Controller)); i++) {
			if (connectedControllers[i].ControllerStatus == ACTIVE) {
				if (connectedControllers[i].userIndex == user) {
					c = &connectedControllers[i];
					b = connectedControllers[i].currentState;
					break;
				}
			}
		}

		if (!c)
			return status;

		// Send to server
		if (pVibration != nullptr) {
			// userIndex might have flags (like 0xFF), mask them out if necessary, 
			// though usually SetState receives a clean index (0-3).
			int cleanIndex = user & 0xFF;

			if (cleanIndex < 4) {
				SendVibrationUpdate(cleanIndex, pVibration->wLeftMotorSpeed, pVibration->wRightMotorSpeed);
			}
		}
		else {
			// If pVibration is null, it usually implies stop (0,0)
			SendVibrationUpdate(user & 0xFF, 0, 0);
		}

		return ERROR_SUCCESS;
	}

    return status;
}

// fix for inactivity (screen dimming)
int XamInactivityDetectRecentActivityHook(DWORD r3) {
	// check if a controller is connected
	for (int i = 0; i < 4; i++) {
		if (connectedControllers[i].ControllerStatus == ACTIVE) {
			// return active
			return 1;
		}
	}
	return XamInactivityDetectRecentActivityDetour.GetOriginal<decltype(&XamInactivityDetectRecentActivityHook)>()(r3);
}

bool ReadConfig()
{
	if (gotIp) return true;

	FILE* file = fopen(pluginPath, "r");
	if (!file)
	{
		OutputDebugStringA("Failed to open config file.\n");
		return false;
	}

	char buffer[256];

	while (fgets(buffer, sizeof(buffer), file))
	{
		buffer[strcspn(buffer, "\r\n")] = 0;

		if (strlen(buffer) == 0 || buffer[0] == '#')
			continue;

		char lower[256];
		strcpy(lower, buffer);
		for (char* p = lower; *p; ++p)
			*p = (char)tolower(*p);

		if (strncmp(lower, "ip=", 3) == 0)
		{
			strcpy(ip, buffer + 3);
		}
		else if (strncmp(lower, "port=", 5) == 0)
		{
			port = atoi(buffer + 5);
		}
	}

	fclose(file);
	gotIp = true;

	return TRUE;
}

DWORD WINAPI StartWSConnection(LPVOID) {
    XNetStartupParams xnsp;
    memset(&xnsp, 0, sizeof(xnsp));
    xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
    xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

    // 1. MOVED UP: Initialize Network Stack ONCE
    // Note: It is safer to use NetDll_WSAStartup with the SYSAPP caller ID 
    // to match your other NetDll calls, but standard WSAStartup often maps similarly.
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    if (wsaResult != 0) {
        DbgPrint("[WirelessInput360] CRITICAL: WSAStartup failed: %d\n", wsaResult);
        return 0; // Cannot run without network stack
    }

    // 2. Check config once (or move inside if config changes dynamically)
    if (!ReadConfig()) {
        NetDll_WSACleanup(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP));
        return 0;
    }

    // Outer loop for Reconnection Logic
    while (g_ClientThreadRunning) {
        
        // Create Socket
        SOCKET sock = NetDll_socket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            DbgPrint("[WirelessInput360] socket creation failed: %d\n", NetDll_WSAGetLastError());
            // Do NOT Cleanup WSA here, just sleep and retry the socket creation
            Sleep(3000);
            continue;
        }

        BOOL opt_true = TRUE;
        NetDll_setsockopt(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, SOL_SOCKET, 0x5801, (PCSTR)&opt_true, sizeof(BOOL));

        // --- Connect to server ---
        SOCKADDR_IN target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip);

        if (NetDll_connect(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, (SOCKADDR*)&target, sizeof(target)) == SOCKET_ERROR) {
            DbgPrint("[WirelessInput360] connect failed. Retrying in 3s...\n");
            NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
            Sleep(3000);
            continue;
        }
        DbgPrint("[WirelessInput360] Connected to server\n");

        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

        char wsHandshake[512];
        sprintf(
            wsHandshake,
            "GET / HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
            ip, port
        );

        if (NetDll_send(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, wsHandshake, strlen(wsHandshake), 0) == SOCKET_ERROR) {
            DbgPrint("[WirelessInput360] Handshake send failed\n");
            NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
            Sleep(3000);
            continue;
        }

        const int BUFSIZE = 4096;
        char buf[BUFSIZE];
        int bytes = NetDll_recv(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, buf, BUFSIZE - 1, 0);

        if (bytes <= 0) {
            DbgPrint("[WirelessInput360] Handshake recv failed / server closed\n");
            NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
            Sleep(3000);
            continue;
        }
        // ... Handshake processing ...
        DbgPrint("[WirelessInput360] Handshake response received\n");

		g_ServerSocket = sock;

        // --- WebSocket main loop ---
        bool connectionActive = true;
        
        while (connectionActive && g_ClientThreadRunning) { // Add global check here too
            bytes = NetDll_recv(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, buf, BUFSIZE - 1, 0);
            if (bytes > 0) {
				// simple text frame decoding
				unsigned char* data = (unsigned char*)buf;
				int opcode = data[0] & 0x0F;
				int masked = data[1] & 0x80;
				int payloadLen = data[1] & 0x7F;
				int offset = 2;

				if (payloadLen == 126 && bytes >= 4) {
					payloadLen = (data[2] << 8) | data[3];
					offset += 2;
				}
				else if (payloadLen == 127 && bytes >= 10) {
					payloadLen = 0;
					for (int i = 0; i < 8; ++i)
						payloadLen = (payloadLen << 8) | data[offset++];
				}

				if (masked) {
					unsigned char mask[4];
					memcpy(mask, data + offset, 4);
					offset += 4;
					for (int i = 0; i < payloadLen; ++i)
						data[offset + i] ^= mask[i % 4];
				}

				static char prevText[256] = { 0 };

				// Print text frames only
				if (opcode == 1) {
					char text[256];
					if (payloadLen > 255) payloadLen = 255;
					memcpy(text, data + offset, payloadLen);
					text[payloadLen] = '\0';

					if (text[0] != '\0') {
						int pStatus = text[0] - '0'; // State
						int pNum = text[1] - '0';

						if (pStatus == 1) {
							if (connectedControllers[pNum].ControllerStatus == ACTIVE) {
								RemoveDevice(pNum);
							}
							continue;
						}

						if (connectedControllers[pNum].ControllerStatus == INACTIVE) {
							AddDevice(pNum);
						}

						uint8_t raw[128];
						int raw_len = 0;

						for (int i = 0; text[i] && text[i + 1]; i += 2) {
							char buf[3] = { text[i], text[i + 1], 0 }; // take 2 chars + null
							raw[raw_len++] = (uint8_t)strtol(buf, NULL, 16);
						}

						ButtonsReport buttonReport = *(ButtonsReport*)raw;

						connectedControllers[pNum].currentState = buttonReport;
					}
				}
				else if (opcode == 8) {
					connectionActive = false;
				}
			}
			else {
				// Connection lost or error
				connectionActive = false;
			}
		}

		g_ServerSocket = INVALID_SOCKET;

		// Close the socket, but keep WSA loaded for the next attempt
		NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
		DbgPrint("[WirelessInput360] Connection lost. Retrying in 3s...\n");
		Sleep(3000);
	}
	NetDll_WSACleanup(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP));
	return 0;
}

void* XamInputGetState = nullptr;
void* XamInputGetCapabilitiesEx = nullptr;
void* XamInputSetState = nullptr;
bool isDevkit = true;

bool initFunctionPointers() {
	isDevkit = *(uint32_t*)(0x8010D334) == 0x00000000;
	HANDLE kernelHandle = GetModuleHandleA("xboxkrnl.exe");

	if (!kernelHandle) {
		DbgPrint("[WirelessInput360] COULDNT GET KERNEL HANDLE!\n");
		return false;
	}

	HANDLE xamHandle = GetModuleHandleA("xam.xex");

	XexGetProcedureAddress(kernelHandle, 189, &MmFreePhysicalMemory);

	XexGetProcedureAddress(xamHandle, 685, &XamInputGetCapabilitiesEx);
	XexGetProcedureAddress(xamHandle, 401, &XamInputGetState);
	XexGetProcedureAddress(xamHandle, 402, &XamInputSetState);

	if (isDevkit) {
		DbgPrint("[WirelessInput360] Running in devkit mode\n");
		XamUserBindDeviceCallback = (xam_user_bind_device_callback_func_t)0x817A34B8; // 7C 8B 23 78 7C A4 2B 78 54 CA 06 3F
		XampInputRoutedToSysapp = (DWORD*)0x81D4F650;
	}
	else {
		DbgPrint("[WirelessInput360] Running in retail mode\n");
		XamUserBindDeviceCallback = (xam_user_bind_device_callback_func_t)0x816D9060; // 7C 8B 23 78 7C A4 2B 78 54 CA 06 3F
		XampInputRoutedToSysapp = (DWORD*)0x81AAC2A0;
	}
	return true;
}

void NormalizePath(char* pluginPath)
{
	// 1. Define struct locally
	typedef struct {
		const char* mount;
		const char* device;
	} MountMapping;

	// 2. Define data locally as STATIC (initialized only once)
	// Put the longest paths (like DEVKIT or Games) ABOVE generic Hdd/Mass paths
	static const MountMapping driveMappings[] = {
		{ MOUNT_DEVKIT,    DEVICE_DEVKIT },
		{ MOUNT_HDDGAMES,  DEVICE_HDDGAMES },
		{ MOUNT_HDDAPPS,   DEVICE_HDDAPPS },
		{ MOUNT_USBMU0,    DEVICE_USBMU0 },
		{ MOUNT_USBMU1,    DEVICE_USBMU1 },
		{ MOUNT_USBMU2,    DEVICE_USBMU2 },
		{ MOUNT_HDD,       DEVICE_HARDISK0_PART1 },
		{ MOUNT_USB0,      DEVICE_USB0 },
		{ MOUNT_USB1,      DEVICE_USB1 },
		{ MOUNT_USB2,      DEVICE_USB2 },
		{ MOUNT_INTMU,     DEVICE_INTMEM },
		{ MOUNT_DVD,       DEVICE_CDROM0 },
		{ MOUNT_FLASH,     DEVICE_NAND_FLASH },
		{ MOUNT_MMCMU,     DEVICE_MMCMU },
		{ MOUNT_FLASHMU,   DEVICE_FLASHMU },
		{ MOUNT_MU,        DEVICE_MEMORY_UNIT0 },
		{ MOUNT_MU1,       DEVICE_MEMORY_UNIT1 },
		{ NULL, NULL }
	};

	int i;

	// 3. The Loop
	for (i = 0; driveMappings[i].mount != NULL; i++)
	{
		const char* devicePrefix = driveMappings[i].device;
		const char* mountPoint = driveMappings[i].mount;
		size_t devLen = strlen(devicePrefix);

		if (strncmp(pluginPath, devicePrefix, devLen) == 0)
		{
			// Ensure we matched a full directory name
			if (pluginPath[devLen] == '\\' || pluginPath[devLen] == '\0')
			{
				char temp[MAX_PATH];
				const char* remainingPath = pluginPath + devLen;

				// Skip the leading slash if present so we don't get "Hdd:\\folder"
				if (*remainingPath == '\\') {
					remainingPath++;
				}

				// Combine: "Hdd:" + "\" + "MyPath"
				sprintf(temp, "%s\\%s", mountPoint, remainingPath);

				strcpy(pluginPath, temp);
				return; // Stop processing once match is found
			}
		}
	}
}

BOOL DllMain(HINSTANCE hModule, DWORD reason, void* pReserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		if ((XboxKrnlVersion->Build != 17559 && XboxKrnlVersion->Build != 17489) || IsTrayOpen()) {
			DbgPrint("[WirelessInput360] Only 17559 and 17489 dashboards are currently supported or the disk tray is open. Aborting launch...\n");
			return FALSE;
		}

		if (!initFunctionPointers())
			return FALSE;

		if (isDevkit) {
			XamInactivityDetectRecentActivityDetour = Detour((void*)0x81750588, (void*)XamInactivityDetectRecentActivityHook); // 3D 60 81 ?? 3D 40 81 ?? E8 6B ?? ?? E9 6A ?? ?? 7F 23 58 40 40 98 00 0C
		}
		else {
			XamInactivityDetectRecentActivityDetour = Detour((void*)0x81695DE8, (void*)XamInactivityDetectRecentActivityHook); // 3D 60 81 ?? 3D 40 81 ?? E8 6B ?? ?? E9 6A ?? ?? 7F 23 58 40 40 98 00 0C
		}

		LDR_DATA_TABLE_ENTRY* pDataTable = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(hModule);

		WideCharToMultiByte(CP_ACP, 0, pDataTable->FullDllName.Buffer, -1, pluginPath, MAX_PATH, nullptr, nullptr);

		char* lastSlash = strrchr(pluginPath, '\\');
		if (lastSlash)
		{
			*(lastSlash + 1) = '\0';
		}

		NormalizePath(pluginPath);

		strcat(pluginPath, "WirelessInput360.ini");

		XamInputGetStateDetour = Detour(XamInputGetState, (void*)XamInputGetStateHook);
		XamInputGetCapabilitiesDetour = Detour(XamInputGetCapabilitiesEx, (void*)XamInputGetCapabilitiesExHook);
		XamInputSetStateDetour = Detour(XamInputSetState, (void*)XamInputSetStateHook);

		XamInputGetStateDetour.Install();
		XamInputGetCapabilitiesDetour.Install();
		XamInputSetStateDetour.Install();
		XamInactivityDetectRecentActivityDetour.Install();

		DbgPrint("[WirelessInput360] Hooks installed\n");

		ExCreateThread(nullptr, 0, nullptr, nullptr, StartWSConnection, nullptr, 2);
	}
	else if (reason == DLL_PROCESS_DETACH) {
		XamInputGetStateDetour.Remove();
		XamInputGetCapabilitiesDetour.Remove();
		XamInputSetStateDetour.Remove();
		XamInactivityDetectRecentActivityDetour.Remove();

		port = 3000;
		gotIp = false;
		g_ClientThreadRunning = 0;

		for (int i = 0; i < (sizeof(connectedControllers) / sizeof(Controller)); i++) {
			if (connectedControllers[i].ControllerStatus == ACTIVE) {
				RemoveDevice(i);
			}
		}
	}
	return TRUE;
}