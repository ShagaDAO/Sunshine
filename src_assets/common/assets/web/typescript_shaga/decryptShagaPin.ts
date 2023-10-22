// decryptShagaPin.ts

import { EncryptionManager } from './encryptionManager';
import bs58 from 'bs58';
import { sharedState } from './sharedState';
import { PublicKey } from "@solana/web3.js";
import { connection, ServerManager } from "./serverManager";
import { Affair, AffairState } from "../../../../../third-party/shaga-program/app/shaga_joe/src/generated";


// Parameters for retry delay & timeout
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const timeLimit = 30000; // 15 seconds

async function verifyRentalPayment(
  affairAccountPublicKey: PublicKey,
  receivedPublicKey: PublicKey
): Promise<boolean> {
  try {
    // Log the types and values for debugging
    console.log(`affairAccountPublicKey is: ${affairAccountPublicKey.toString()} and type: ${typeof affairAccountPublicKey}`);
    console.log(`receivedPublicKey is: ${receivedPublicKey.toString()} and type: ${typeof receivedPublicKey}`);

    // Fetch affair data
    const affairData = await Affair.fromAccountAddress(connection, affairAccountPublicKey);
    console.log(`Fetched affair data: ${JSON.stringify(affairData)}`);

    // Validate affair state
    if (affairData.affairState !== AffairState.Unavailable) {
      console.error(`Affair state is invalid. Expected: Unavailable, Got: ${AffairState[affairData.affairState]}`);
      return false;
    }

    // Validate client public key
    if (affairData.client.toString() !== receivedPublicKey.toString()) {
      console.error("Client public keys mismatch.");
      return false;
    }

    return true;

  } catch (error) {
    console.error(`Exception caught in verifyRentalPayment: ${error}`);
    return false;
  }
}

// TODO: This logic is too fragile to stay on the frontend, v2 moves everything to the C++ backemd
export async function decryptPINAndVerifyPayment(
  encryptedPIN: string,
  base58ClientEdPublicKey: string,
  base58ClientXPublicKey: string
): Promise<Error | null> {

  // Log the received encrypted PIN and public keys for debugging
  console.log("Received encryptedPin: ", encryptedPIN);
  console.log("Received Ed25519 publicKey in Base58: ", base58ClientEdPublicKey);
  console.log("Received X25519 publicKey in Base58: ", base58ClientXPublicKey);

  // Step 1: Check if the server's private key is loaded.
  if (sharedState.sharedKeypair === null) {
    return new Error('Server private key not loaded');
  }

  // Step 2: Decode the encrypted PIN and client's public keys.
  let decodedEncryptedPin: Uint8Array;
  let clientEdPublicKeyBytes: Uint8Array;
  let clientXPublicKeyBytes: Uint8Array;
  try {
    decodedEncryptedPin = await EncryptionManager.hexToBytes(encryptedPIN);
    console.log("Decoded encryptedPin in Bytes:", Buffer.from(decodedEncryptedPin).toString('hex'));

    clientEdPublicKeyBytes = new Uint8Array(bs58.decode(base58ClientEdPublicKey));
    console.log("Decoded Ed25519 publicKey in Bytes:", Buffer.from(clientEdPublicKeyBytes).toString('hex'));

    clientXPublicKeyBytes = new Uint8Array(bs58.decode(base58ClientXPublicKey));
    console.log("Decoded X25519 publicKey in Bytes:", Buffer.from(clientXPublicKeyBytes).toString('hex'));

  } catch (e: unknown) {
    if (e instanceof Error) {
      return new Error('Decoding failed: ' + e.message);
    } else {
      return new Error('Decoding failed');
    }
  }
  // Step 3: Validate required variables.
  if (!decodedEncryptedPin || !clientEdPublicKeyBytes || !clientXPublicKeyBytes || !sharedState.sharedKeypair?.secretKey) {
    return new Error('Required variables are undefined');
  }
  // Step 4: Decrypt the PIN using the X25519 key.
  const decryptedPIN = await EncryptionManager.decryptPIN(decodedEncryptedPin, sharedState.sharedKeypair, clientXPublicKeyBytes);
  // Step 5: Verify the rent payment.
  const startTime = Date.now();
  while (Date.now() - startTime < timeLimit) {
    if (sharedState.affairAccountPublicKey) {
      const isPaymentVerified = await verifyRentalPayment(new PublicKey(sharedState.affairAccountPublicKey), new PublicKey(base58ClientEdPublicKey));
      if (isPaymentVerified) {
        // Step 6: Send decrypted PIN to backend.
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

  // Step 7: Handle timeout.
  if (Date.now() - startTime >= timeLimit) {
    return new Error('Rent payment timed out. Cannot proceed.');
  }

  return null;  // Success
}
