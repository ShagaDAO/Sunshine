#include "store_encrypted.h"
#include <fstream>
#include <iostream>

namespace shaga {
  void store_encrypted_mnemonic(const std::string& encrypted_mnemonic) {
    std::ofstream file("secure_mnemonic_storage.txt", std::ios::app); // Opening in append mode
    if (file.is_open()) {
      file << encrypted_mnemonic << std::endl;
      file.close();
    } else {
      std::cout << "Failed to open the file for storage." << std::endl;
    }
  }

  void store_encrypted_keypair(const std::string& encrypted_keypair) {
    std::ofstream file("secure_ed25519_storage.txt", std::ios::app); // Opening in append mode
    if (file.is_open()) {
      file << encrypted_keypair << std::endl;
      file.close();
    } else {
      std::cout << "Failed to open the file for storage." << std::endl;
    }
  }


}
