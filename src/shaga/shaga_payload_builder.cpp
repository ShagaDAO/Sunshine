#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <Winsock2.h>
#include <iostream>
#include <string>
#include <curl/curl.h>

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

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}

std::string getLocalIPAddress() {
  CURL* curl;
  CURLcode res;
  std::string readBuffer;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://api.ipify.org");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if(res != CURLE_OK) {
      throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
    }
  } else {
    throw std::runtime_error("CURL initialization failed.");
  }

  return readBuffer;
}


// Helper function for fetching the CPU name.
std::string getCPUName() {
  CPUInfoDelegate cpuInfoDelegate;
  std::vector<CPUInfo> cpuInfoVector = cpuInfoDelegate.cpuInfoVector();
  return !cpuInfoVector.empty() ? cpuInfoVector[0].name() : "";
}


long long convertToBytes(const std::string& capacity) {
  try {
    if (capacity.find("MB") != std::string::npos) {
      return std::stoll(capacity.substr(0, capacity.size() - 2)) * 1024 * 1024;
    }
    else if (capacity.find("Bytes") != std::string::npos) {
      return std::stoll(capacity.substr(0, capacity.size() - 5));
    }
    else {
      std::cerr << "Unknown unit in RAM capacity: " << capacity << std::endl;
      return -1;
    }
  }
  catch (const std::invalid_argument& e) {
    std::cerr << "Invalid RAM capacity value: " << e.what() << std::endl;
    return -1;
  }
  catch (const std::out_of_range& e) {
    std::cerr << "RAM capacity value out of range: " << e.what() << std::endl;
    return -1;
  }
}

// Helper function for fetching the total RAM.
std::pair<int, std::string> getTotalRAM() {
  RAMInfoDelegate ramInfoDelegate;
  std::vector<RAMInfo> ramInfoVector = ramInfoDelegate.ramInfoVector();
  long long totalRam = 0;
  std::string firstValidMemoryType;
  for (const auto& ramInfo : ramInfoVector) {
    long long capacityBytes = convertToBytes(ramInfo.capacity());
    if (capacityBytes != -1) {
      totalRam += capacityBytes;
    }

    if (firstValidMemoryType.empty() && ramInfo.memoryType() != "Unknown" && !ramInfo.memoryType().empty()) {
      firstValidMemoryType = ramInfo.memoryType();
    }
  }
  // Convert totalRam from bytes to MB and ensure it fits into an int
  int totalRamMB = static_cast<int>(totalRam / (1024 * 1024));
  return {totalRamMB, firstValidMemoryType};
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
