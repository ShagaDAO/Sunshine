#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <curl/curl.h>
#include <third-party/nlohmann-json/json.hpp>

#include "third-party/SystemInfo/include/cpuinfodelegate.h"
#include "third-party/SystemInfo/include/raminfodelegate.h"
#include "third-party/SystemInfo/include/gpuinfodelegate.h"

#include "../config.h"
#include "../main.h"
#include "shaga_payload_builder.h"
#include <boost/log/sources/record_ostream.hpp>


size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
  ((std::string*)userp)->append((char*)contents, size * nmemb);
  return size * nmemb;
}


const std::string RAPIDAPI_KEY = "dbee35b62emshd16864d6d9f1b26p173e31jsnddf66b45a8f8";
const std::string RAPIDAPI_HOST = "ip-geo-location.p.rapidapi.com";
const std::string IP_API_URL = "https://ip-geo-location.p.rapidapi.com/ip/check?format=json";


std::pair<std::string, std::string> getIPAddressAndCoordinates() {
  CURL* curl;
  CURLcode res;
  std::string readBuffer;

  curl = curl_easy_init();
  if (!curl) {
    throw std::runtime_error("CURL initialization failed");
  }

  // Set CURL options
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
  curl_easy_setopt(curl, CURLOPT_URL, IP_API_URL.c_str());

#ifdef _WIN32
  // Use native CA on Windows
  curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#endif


  // Add headers
  struct curl_slist* headers = NULL;
  headers = curl_slist_append(headers, ("X-RapidAPI-Key: " + RAPIDAPI_KEY).c_str());
  headers = curl_slist_append(headers, ("X-RapidAPI-Host: " + RAPIDAPI_HOST).c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  // Set up for receiving data
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

  // Execute CURL
  res = curl_easy_perform(curl);

  // Cleanup
  curl_easy_cleanup(curl);

  // Check response
  if (res != CURLE_OK) {
    throw std::runtime_error("CURL execution failed: " + std::string(curl_easy_strerror(res)));
  }

  // Parse JSON
  nlohmann::json json = nlohmann::json::parse(readBuffer);

  // Extract IP address
  if (json.find("ip") == json.end()) {
    throw std::runtime_error("JSON does not contain IP address");
  }
  std::string ipAddress = json["ip"];

  // Extract and format latitude and longitude
  if (json.find("location") == json.end() ||
      json["location"].find("latitude") == json["location"].end() ||
      json["location"].find("longitude") == json["location"].end()) {
    throw std::runtime_error("JSON does not contain latitude or longitude");
  }
  double latitude = json["location"]["latitude"];
  double longitude = json["location"]["longitude"];

  std::ostringstream stream;
  stream << std::fixed << std::setprecision(3) << latitude << "," << longitude;

  return {ipAddress, stream.str()};
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
    std::string capacityStr = ramInfo.capacity();
    if (capacityStr == "Unknown") {
      continue;
    }

    std::size_t startPos = capacityStr.find("(");
    std::size_t endPos = capacityStr.find(" Bytes)");
    if (startPos == std::string::npos || endPos == std::string::npos) {
      continue; // Skip if the capacity is not in the expected format
    }

    std::string byteCountStr = capacityStr.substr(startPos + 1, endPos - startPos - 1);
    long long capacityBytes = std::stoll(byteCountStr); // Convert the string to long long

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

  // Fetch both IP address and coordinates
  auto [ipAddress, coordinates] = getIPAddressAndCoordinates();

  payload.ipAddress = ipAddress;
  payload.coordinates = coordinates;

  payload.cpuName = getCPUName();
  auto [totalRam, firstValidMemoryType] = getTotalRAM();
  payload.totalRamMB = totalRam;
  payload.firstValidMemoryType = firstValidMemoryType;
  payload.gpuName = getGPUName();

  return payload;
}
