// createWallet.ts

import * as bip39 from 'bip39';
import { Keypair } from "@solana/web3.js";
import { EncryptionManager } from './encryptionManager';
import { ServerManager } from './serverManager';
import { SolanaManager } from './serverManager';
import { fetchAndDisplayBalance, getWalletStatus, loadAndDecryptKeypair, messageDisplay } from "./shagaUIManager";
import { sharedState } from "./sharedState";



// Mnemonic generation utility
class MnemonicManager {
  generate(): string {
    return bip39.generateMnemonic();
  }

  generateKeypair(mnemonic: string): Keypair {
    const seed = bip39.mnemonicToSeedSync(mnemonic, "");
    return Keypair.fromSeed(seed.slice(0, 32));
  }
}

// Centralized error handling
function handleError(error: string): void {
  console.error(error);
  messageDisplay.className = 'alert alert-danger';
  messageDisplay.innerHTML = error;
}


// Password verification TODO: refactor in accountUtility.ts
export async function verifyPassword(password: string): Promise<boolean> {
  const response = await fetch('/api/verify_password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ password })
  });
  return response.status === 200;
}

// The main createWallet function
export async function createWallet() {
  console.log("createWallet called"); // Debug
  // First, check if a wallet already exists
  const hasWallet = await getWalletStatus();
  if (hasWallet) {
    handleError('A wallet already exists. Cannot create a new one.');
    return;
  }

  const reEnteredPassword = prompt("Please re-enter your password:");
  if (reEnteredPassword === null) {
    handleError('Password prompt cancelled.');
    return;
  }

  // Password verification
  const isVerified = await verifyPassword(reEnteredPassword);
  if (isVerified) {
    messageDisplay.innerHTML = "Password verified, creating wallet...";

    const mnemonicManager = new MnemonicManager();
    const mnemonic = mnemonicManager.generate();

    const keypair = mnemonicManager.generateKeypair(mnemonic);
    // Generate Keypair and public key
    const renamedKeypair = {
      ed25519PublicKey: keypair.publicKey.toBuffer(),  // Converted to Uint8Array
      ed25519PrivateKey: keypair.secretKey,  // Already Uint8Array
    };
    const encryptedKeypair = await EncryptionManager.encryptED25519Keypair(renamedKeypair, reEnteredPassword);
    // Check if the encryption was successful
    if (encryptedKeypair === null) {
      handleError("Keypair encryption failed!");
      return;
    }

    const encryptionResult = await EncryptionManager.encryptMnemonic(mnemonic, reEnteredPassword);
    const decryptedMnemonic = EncryptionManager.decryptMnemonic(encryptionResult, reEnteredPassword);

    if (decryptedMnemonic === null) {
      handleError("Decryption failed!");
      return;
    }

    console.log(`Wallet Created. Public Key: ${keypair.publicKey}`);
    // Fetch and display the balance of the new wallet
    const balance = await SolanaManager.getBalance(keypair.publicKey);
    if (balance !== null) {
      console.log(`Initial Wallet Balance: ${balance} LAMPORTS`);
    } else {
      console.log("Failed to fetch wallet balance.");
    }
    // Store the encrypted mnemonic and keypair
    await ServerManager.postEncryptedMnemonicToServer(encryptionResult.encrypted);
    await ServerManager.postEncryptedKeypairToServer(encryptedKeypair);
    // Make an API call to store the wallet status as 'true' (indicating a wallet has been created)
    try {
      const response = await fetch('/api/store_wallet_status', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify('true'),
      });

      if (!response.ok) {
        throw new Error('Failed to store wallet status.');
      }
    } catch (error) {
      console.error('Error while storing wallet status:', error);
    }
    // After successful wallet creation
    messageDisplay.className = 'alert alert-success';
    messageDisplay.innerHTML = `Wallet Created. Public Key: ${keypair.publicKey}`;
    await loadAndDecryptKeypair(reEnteredPassword);
    await fetchAndDisplayBalance();

  } else {
    messageDisplay.innerHTML = "Invalid password.";
    handleError('Invalid password.');
  }
}
