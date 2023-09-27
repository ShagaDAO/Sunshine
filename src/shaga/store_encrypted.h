#pragma once

#include <string>

namespace shaga {
  // Function to store the encrypted mnemonic
  void store_encrypted_mnemonic(const std::string& encrypted_mnemonic);

  // Function to store the encrypted keypair
  void store_encrypted_keypair(const std::string& encrypted_keypair);
}
