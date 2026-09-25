// small cpp project i use this langauge in a lot of projects along with a bunch of c# i use visual studio to build exe's and vs code i also do personall stress testing & vuln testing 
// i usually make my programs very hard to reverse with anti tamper and anti vm and personally test in ida and virtual machines (for code to do with my cheats not usual programs)
// was going to make a short cod cheat (hacks) but would require a driver and all my vuln windows drivers are patched... 
// im less skilled at c++ as it requires 10x the writing but im better at html,css,js and python is very easy for me now

#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <Lmcons.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")

// same as my python b() function js quicker for blank lines
void b() {
    std::cout << "\n";
}

std::string getComputerName() {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(name);

    if (GetComputerNameA(name, &size)) {
        return name;
    }

    return "Unknown";
}

std::string getUsername() {
    char username[UNLEN + 1];
    DWORD size = UNLEN + 1;

    if (GetUserNameA(username, &size)) {
        return username;
    }

    return "Unknown";
}

// grabs the cpu brand info in parts then puts it into one string
std::string getCPU() {
    int cpuInfo[4] = {0};
    char cpuBrand[0x40] = {0};

    __cpuid(cpuInfo, 0x80000000);
    unsigned int maxId = cpuInfo[0];

    if (maxId >= 0x80000004) {
        __cpuid(cpuInfo, 0x80000002);
        memcpy(cpuBrand, cpuInfo, sizeof(cpuInfo));

        __cpuid(cpuInfo, 0x80000003);
        memcpy(cpuBrand + 16, cpuInfo, sizeof(cpuInfo));

        __cpuid(cpuInfo, 0x80000004);
        memcpy(cpuBrand + 32, cpuInfo, sizeof(cpuInfo));

        return cpuBrand;
    }

    return "Unknown CPU";
}

// gets memory from windows then converts the bytes into gb
void showRAM() {
    MEMORYSTATUSEX memory;
    memory.dwLength = sizeof(memory);

    if (GlobalMemoryStatusEx(&memory)) {
        double totalRAM = static_cast<double>(memory.ullTotalPhys) / (1024 * 1024 * 1024);
        double freeRAM = static_cast<double>(memory.ullAvailPhys) / (1024 * 1024 * 1024);

        std::cout << "Total RAM: " << totalRAM << " GB\n";
        std::cout << "Available RAM: " << freeRAM << " GB\n";
        std::cout << "Memory Usage: " << memory.dwMemoryLoad << "%\n";
    }
}

std::string getGPU() {
    DISPLAY_DEVICEA device;
    ZeroMemory(&device, sizeof(device));
    device.cb = sizeof(device);

    if (EnumDisplayDevicesA(NULL, 0, &device, 0)) {
        return device.DeviceString;
    }

    return "Unknown GPU";
}

// checks which architecture windows is actually running on
std::string getArchitecture() {
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);

    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        return "64-bit (x64)";
    } else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        return "64-bit (ARM64)";
    } else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        return "32-bit (x86)";
    } else {
        return "Unknown";
    }
}

void showWindowsVersion() {
    DWORD version = GetVersion();
    DWORD major = static_cast<DWORD>(LOBYTE(LOWORD(version)));
    DWORD minor = static_cast<DWORD>(HIBYTE(LOWORD(version)));

    std::cout << "Windows Version: " << major << "." << minor << "\n";
    std::cout << "Architecture: " << getArchitecture() << "\n";
}

// starts as milliseconds then converts it down into actual readable uptime
void showUptime() {
    ULONGLONG milliseconds = GetTickCount64();
    ULONGLONG seconds = milliseconds / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    hours %= 24;
    minutes %= 60;

    std::cout << "Uptime: " << days << "d " << hours << "h " << minutes << "m\n";
}

bool isAdministrator() {
    BOOL admin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {

        CheckTokenMembership(NULL, adminGroup, &admin);
        FreeSid(adminGroup);
    }

    return admin;
}

// winsock gets our hostname then resolves it into the local ipv4
std::string getLocalIP() {
    WSADATA data;

    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return "Unavailable";
    }

    char hostname[256];

    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        WSACleanup();
        return "Unavailable";
    }

    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) {
        WSACleanup();
        return "Unavailable";
    }

    sockaddr_in* address = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    char ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(address->sin_addr), ip, sizeof(ip));

    std::string finalIP = ip;

    freeaddrinfo(result);
    WSACleanup();

    return finalIP;
}

// goes through drive letters and only shows the ones that actually exist
void showDrives() {
    DWORD drives = GetLogicalDrives();

    for (char letter = 'A'; letter <= 'Z'; letter++) {
        if (drives & (1 << (letter - 'A'))) {
            std::string path;
            path += letter;
            path += ":\\";

            ULARGE_INTEGER freeBytes;
            ULARGE_INTEGER totalBytes;

            if (GetDiskFreeSpaceExA(path.c_str(), nullptr, &totalBytes, &freeBytes)) {
                double totalGB = static_cast<double>(totalBytes.QuadPart) / (1024 * 1024 * 1024);
                double freeGB = static_cast<double>(freeBytes.QuadPart) / (1024 * 1024 * 1024);

                std::cout << letter << ": Total: " << totalGB << " GB | Free: " << freeGB << " GB\n";
            }
        }
    }
}

void systemInformation() {
    system("cls");
    std::cout << "========== SYSTEM INFORMATION ==========\n";
    b();

    std::cout << "Computer Name: " << getComputerName() << "\n";
    std::cout << "Username: " << getUsername() << "\n";
    showWindowsVersion();
    std::cout << "Administrator: " << (isAdministrator() ? "Yes" : "No") << "\n";
    showUptime();

    b();
    system("pause");
}

void hardwareInformation() {
    system("cls");
    std::cout << "========== HARDWARE INFORMATION ==========\n";
    b();

    std::cout << "CPU: " << getCPU() << "\n";
    std::cout << "GPU: " << getGPU() << "\n";

    b();
    showRAM();
    b();

    std::cout << "Drives:\n";
    showDrives();

    b();
    system("pause");
}

// public ip and isp gonna add later since that needs an external request
void networkInformation() {
    system("cls");
    std::cout << "========== NETWORK INFORMATION ==========\n";
    b();

    std::cout << "Local IP: " << getLocalIP() << "\n";
    std::cout << "Public IP: doing this later... (external api request required)\n";
    std::cout << "ISP: doing this later... (external api request required)\n";

    b();
    system("pause");
}

void securityInformation() {
    system("cls");
    std::cout << "========== SECURITY CHECK ==========\n";
    b();

    std::cout << "Running as Administrator: " << (isAdministrator() ? "YES" : "NO") << "\n";
    std::cout << "Architecture: " << getArchitecture() << "\n";

    b();
    system("pause");
}

// basically runs all our info functions together for one big report
void fullReport() {
    system("cls");

    std::cout << "========================================\n";
    std::cout << "             FULL REPORT\n";
    std::cout << "========================================\n";
    b();

    std::cout << "[ SYSTEM ]\n";
    std::cout << "Computer: " << getComputerName() << "\n";
    std::cout << "Username: " << getUsername() << "\n";
    std::cout << "Architecture: " << getArchitecture() << "\n";
    showUptime();

    b();

    std::cout << "[ HARDWARE ]\n";
    std::cout << "CPU: " << getCPU() << "\n";
    std::cout << "GPU: " << getGPU() << "\n";
    showRAM();

    b();

    std::cout << "[ NETWORK ]\n";
    std::cout << "Local IP: " << getLocalIP() << "\n";
    std::cout << "Public IP: doing this later... (external api request required)\n";
    std::cout << "ISP: doing this later... (external api request required)\n";

    b();

    std::cout << "[ SECURITY ]\n";
    std::cout << "Administrator: " << (isAdministrator() ? "Yes" : "No") << "\n";

    b();

    std::cout << "[ STORAGE ]\n";
    showDrives();

    b();
    system("pause");
}

// main program starts here then keeps looping the menu until 0 breaks it
int main() {
    while (true) {
        system("cls");

        std::cout << "========================================\n";
        std::cout << "          SYSTEM INSPECTOR v1\n";
        std::cout << "========================================\n";
        b();

        std::cout << "[1] System Information\n";
        std::cout << "[2] Hardware Information\n";
        std::cout << "[3] Network Information\n";
        std::cout << "[4] Quick Security Check\n";
        std::cout << "[5] Full Report\n";
        std::cout << "[0] Exit\n";
        b();

        int choice;

        std::cout << "> ";
        std::cin >> choice;

        // basically same kinda if/elif menu logic as my python project
        if (choice == 1) {
            systemInformation();
        } else if (choice == 2) {
            hardwareInformation();
        } else if (choice == 3) {
            networkInformation();
        } else if (choice == 4) {
            securityInformation();
        } else if (choice == 5) {
            fullReport();
        } else if (choice == 0) {
            std::cout << "\nClosing System Inspector...\n";
            break;
        } else {
            std::cout << "\nInvalid option.\n";
            system("pause");
        }
    }

    return 0;
}
