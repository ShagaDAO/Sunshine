/**
 * @file src/confighttp.h
 * @brief todo
 */
#pragma once

#include <functional>
#include <string>

#include "thread_safe.h"

#define WEB_DIR SUNSHINE_ASSETS_DIR "/web/"

namespace confighttp {


  class SharedState {
  private:
    std::mutex state_mutex;
    std::string encryptedPinShared;
    std::string publicKeyShared;
    std::string received_decryptedPin;
    bool is_initialized;

  public:
    SharedState() : is_initialized(false) {} // constructor to set is_initialized to false

    void initialize() {
      std::lock_guard<std::mutex> lock(state_mutex);
      encryptedPinShared = "";
      publicKeyShared = "";
      received_decryptedPin = "";
      is_initialized = true;
    }

    bool isNull() {
      std::lock_guard<std::mutex> lock(state_mutex);
      return !is_initialized;
    }

    void setEncryptedPinAndKey(const std::string& pin, const std::string& key);
    std::pair<std::string, std::string> getEncryptedPinAndKey();
    void setReceivedDecryptedPin(const std::string& pin);
    std::string getReceivedDecryptedPin();
  };


  constexpr auto PORT_HTTPS = 1;
  void
  start();
  std::string postDataToFrontend(const std::string& encryptedPin, const std::string& publicKey);
}  // namespace confighttp

// mime types map
const std::map<std::string, std::string> mime_types = {
  { "css", "text/css" },
  { "gif", "image/gif" },
  { "htm", "text/html" },
  { "html", "text/html" },
  { "ico", "image/x-icon" },
  { "jpeg", "image/jpeg" },
  { "jpg", "image/jpeg" },
  { "js", "application/javascript" },
  { "json", "application/json" },
  { "png", "image/png" },
  { "svg", "image/svg+xml" },
  { "ttf", "font/ttf" },
  { "txt", "text/plain" },
  { "woff2", "font/woff2" },
  { "xml", "text/xml" },
};
