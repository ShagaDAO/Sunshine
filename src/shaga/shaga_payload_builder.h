#pragma once  // Pragma once directive for include guard

#include <string>
#include <vector>
#include <utility>

// Forward declaration of classes, assuming they're in their respective header files
class CPUInfo;
class RAMInfo;
class GPUInfo;

struct SystemInfoPayload {
  std::string coordinates;
  std::string ipAddress;
  std::string cpuName;
  std::string gpuName;
  std::string firstValidMemoryType;
  long long totalRamMB = 0;  // Initialized within the struct for safety.
};


// Function to get both the local IP address and coordinates
std::pair<std::string, std::string> getIPAddressAndCoordinates();

// Function to build the payload
SystemInfoPayload buildPayload();
