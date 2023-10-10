// decryptShagaPin.ts

import { EncryptionManager } from './encryptionManager';
import bs58 from 'bs58';
import { sharedState } from './sharedState';
import { PublicKey } from "@solana/web3.js";
import { connection } from "./serverManager";
import { Affair, AffairState } from "../../../../../third-party/shaga-program/app/shaga_joe/src/generated";


// Parameters for retry delay & timeout
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const timeLimit = 10000; // 10 seconds

async function verifyRentalPayment(
  affairAccountPublicKey: PublicKey,
  receivedPublicKey: PublicKey
): Promise<boolean> {
  try {
    const affairData = await Affair.fromAccountAddress(connection, affairAccountPublicKey);
    if (affairData.affairState !== AffairState.Available) {
      console.error(`Affair state is not as expected. Current state: ${AffairState[affairData.affairState]}`);
      return false;
    }
    if (affairData.client.toString() !== receivedPublicKey.toString()) {
      console.error('Client public keys do not match.');
      return false;
    }
    return true;
  } catch (error) {
    console.error(`Error in verifyRentalPayment: ${error}`);
    return false;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export async function decryptPINAndVerifyPayment(encryptedPIN: string, publicKey: string): Promise<Error | null> {
  // Step 1: Check if the server's private key is loaded.
  if (sharedState.sharedKeypair === null) {
    return new Error('Server private key not loaded');
  }
  const timeLimit = 10000; // 10 seconds
  const startTime = Date.now();
  // Step 2: Verify the rent payment within a time limit.
  while (Date.now() - startTime < timeLimit) {
    if (sharedState.affairAccountPublicKey) {
      const isPaymentVerified = await verifyRentalPayment(sharedState.affairAccountPublicKey, new PublicKey(publicKey));
      if (isPaymentVerified) {
        // Step 3: Decode the encrypted PIN and client's public key.
        let decodedEncryptedPin: Uint8Array | undefined;
        let clientPublicKey: Uint8Array | undefined;
        // Check if encryptedPIN and publicKey are defined and not empty.
        if (!encryptedPIN || !publicKey) {
          return new Error('encryptedPIN or publicKey is undefined or empty');
        }
        try {
          // Convert the Hex Encoded PIN to Bytes
          decodedEncryptedPin = hexToBytes(encryptedPIN);
          // Decode the Base58 Encoded Public Key
          clientPublicKey = new Uint8Array(bs58.decode(publicKey));
        } catch (e) {
          if (e instanceof Error) {
            return new Error('Decoding failed: ' + e.message);
          } else {
            return new Error('Decoding failed');
          }
        }
        // Make sure decodedEncryptedPin and clientPublicKey are properly initialized.
        if (!decodedEncryptedPin || !clientPublicKey) {
          return new Error('Decoded variables are undefined');
        }
        // Step 4: Decrypt the PIN
        if (!sharedState.sharedKeypair?.secretKey) {
          return new Error('Server private key not loaded');
        }
        const serverPrivateKey = sharedState.sharedKeypair.secretKey;
        const mappedKeys = await EncryptionManager.mapEd25519ToX25519(serverPrivateKey, clientPublicKey);
        // Make sure mappedKeys are properly initialized before proceeding.
        if (!mappedKeys.secretKey || !mappedKeys.publicKey) {
          return new Error('Mapped keys are undefined');
        }
        const decryptedPIN = await EncryptionManager.decryptPinWithX25519PublicKey(decodedEncryptedPin, mappedKeys.secretKey, mappedKeys.publicKey);
        // Step 5: Send the decrypted PIN to the backend via POST.
        try {
          const response = await fetch('https://localhost:47990/shagaPIN', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decryptedPin: decryptedPIN })
          });
          if (!response.ok) {
            return new Error('Failed to send decrypted PIN to backend');
          }
        } catch (error) {
          return new Error('Network error while communicating with backend');
        }
        // Exit the loop since payment is verified and PIN is sent.
        break;
      }
    }
    await delay(500);
  }
  // Step 6: Handle timeout if it occurs.
  if (Date.now() - startTime >= timeLimit) {
    return new Error('Rent payment timed out. Cannot proceed.');
  }

  return null;  // Success is indicated by returning null.
}