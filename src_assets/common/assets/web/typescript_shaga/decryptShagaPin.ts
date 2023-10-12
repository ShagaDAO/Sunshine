// decryptShagaPin.ts

import { EncryptionManager } from './encryptionManager';
import bs58 from 'bs58';
import { sharedState } from './sharedState';
import { PublicKey } from "@solana/web3.js";
import { connection, ServerManager } from "./serverManager";
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

export async function decryptPINAndVerifyPayment(encryptedPIN: string, clientBase58PublicKey: string): Promise<Error | null> { // TODO: This logic is too fragile to stay on the frontend, v2 moves everything to the C++ backemd
  // Step 1: Check if the server's private key is loaded.
  if (sharedState.sharedKeypair === null) {
    return new Error('Server private key not loaded');
  }
  // Step 2: Decode the encrypted PIN and client's public key.
  let decodedEncryptedPin: Uint8Array;
  let clientPublicKeyBytes: Uint8Array;
  try {
    // Convert the Hex Encoded PIN to Bytes
    decodedEncryptedPin = await EncryptionManager.hexToBytes(encryptedPIN);
    // Decode the Base58 Encoded Public Key
    clientPublicKeyBytes = new Uint8Array(bs58.decode(clientBase58PublicKey));
  } catch (e) {
    if (e instanceof Error) {
      return new Error('Decoding failed: ' + e.message);
    } else {
      return new Error('Decoding failed');
    }
  }
  // Step 3: Decrypt the PIN
  if (!decodedEncryptedPin || !clientPublicKeyBytes || !sharedState.sharedKeypair?.secretKey) {
    return new Error('Required variables are undefined');
  }
  const decryptedPIN = await EncryptionManager.decryptAndRetrievePIN(decodedEncryptedPin, sharedState.sharedKeypair.secretKey, clientPublicKeyBytes);
  // Step 4: Verify the rent payment within a time limit.
  const timeLimit = 10000; // 10 seconds
  const startTime = Date.now();
  while (Date.now() - startTime < timeLimit) {
    if (sharedState.affairAccountPublicKey) {
      const isPaymentVerified = await verifyRentalPayment(sharedState.affairAccountPublicKey, new PublicKey(clientBase58PublicKey));
      if (isPaymentVerified) {
        // Step 5: Send the decrypted PIN to the backend via POST.
        try {
          await ServerManager.postShagaPin(decryptedPIN);
        } catch (error) {
          return new Error('Network error while communicating with backend');
        }
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
