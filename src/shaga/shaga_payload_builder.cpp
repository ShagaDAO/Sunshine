#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <Winsock2.h>

#include "third-party/SystemInfo/include/cpuinfodelegate.h"
#include "third-party/SystemInfo/include/raminfodelegate.h"
#include "third-party/SystemInfo/include/gpuinfodelegate.h"

struct SystemInfoPayload {
  std::string ipAddress;
  std::string cpuName;
  std::string gpuName;
  std::string firstValidMemoryType;
  long long totalRamMB = 0;  // Initialized within the struct for safety.
};

std::string getLocalIPAddress() {
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    throw std::runtime_error("WSAStartup failed.");
  }
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    WSACleanup();
    throw std::runtime_error("Socket error.");
  }
  const char* google_dns_server = "8.8.8.8";
  int dns_port = 53;
  sockaddr_in serv;
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(google_dns_server);
  serv.sin_port = htons(dns_port);
  if (connect(sock, (const sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) {
    closesocket(sock);
    WSACleanup();
    throw std::runtime_error("Connection error.");
  }
  sockaddr_in name;
  int namelen = sizeof(name);
  getsockname(sock, (sockaddr*)&name, &namelen);
  const char* p = inet_ntoa(name.sin_addr);
  closesocket(sock);
  WSACleanup();
  if (p != nullptr) {
    return std::string(p);  // Using 'p' directly here
  } else {
    throw std::runtime_error("IP retrieval error.");
  }
}


// Helper function for fetching the CPU name.
std::string getCPUName() {
  CPUInfoDelegate cpuInfoDelegate;
  std::vector<CPUInfo> cpuInfoVector = cpuInfoDelegate.cpuInfoVector();
  return !cpuInfoVector.empty() ? cpuInfoVector[0].name() : "";
}

// Helper function for fetching the total RAM.
std::pair<int, std::string> getTotalRAM() {
  RAMInfoDelegate ramInfoDelegate;
  std::vector<RAMInfo> ramInfoVector = ramInfoDelegate.ramInfoVector();
  long long totalRam = 0;
  std::string firstValidMemoryType;  // Initialize an empty string for the first valid memory type
  for (const auto& ramInfo : ramInfoVector) {
    try {
      totalRam += std::stoi(ramInfo.capacity());  // Convert string to int before addition
      // If we haven't found a valid memory type yet, and the current one is valid, store it
      if (firstValidMemoryType.empty() && ramInfo.memoryType() != "Unknown" && !ramInfo.memoryType().empty()) {
        firstValidMemoryType = ramInfo.memoryType();
      }
    } catch (const std::invalid_argument& e) {
      // Handle conversion error
      std::cerr << "Invalid RAM capacity value: " << e.what() << std::endl;
    } catch (const std::out_of_range& e) {
      // Handle out of range error
      std::cerr << "RAM capacity value out of range: " << e.what() << std::endl;
    }
  }
  return std::make_pair(totalRam, firstValidMemoryType);  // Return the total RAM and first valid memory type
}


// Helper function for fetching the GPU name.
std::string getGPUName() {
  GPUInfoDelegate gpuInfoDelegate;
  std::vector<GPUInfo> gpuInfoVector = gpuInfoDelegate.gpuInfoVector();
  return !gpuInfoVector.empty() ? gpuInfoVector[0].name() : "";
}

SystemInfoPayload buildPayload() {
  SystemInfoPayload payload;

  // Using helper functions to isolate functionalities.
  payload.ipAddress = getLocalIPAddress();
  payload.cpuName = getCPUName();

  // Modify this to include the firstValidMemoryType
  auto [totalRam, firstValidMemoryType] = getTotalRAM();
  payload.totalRamMB = totalRam;
  payload.firstValidMemoryType = firstValidMemoryType;

  payload.gpuName = getGPUName();

  return payload;
}
