// serverManager.ts

import { Connection, PublicKey } from '@solana/web3.js';
import { sharedState, SafeSharedStateType } from "./sharedState";

export const API_BASE_URL = 'https://localhost:47990/api';
export const SOLANA_NETWORK = 'https://api.devnet.solana.com'; // Replace with the correct URL
export let connection = new Connection(SOLANA_NETWORK);


import { SystemInfo } from './shagaUIManager';
import { EncryptResult } from "./encryptionManager";
import bs58 from "bs58";
import { decryptPINAndVerifyPayment } from "./decryptShagaPin";
import { checkRentalState } from "./shagaTransactions";

interface PinResponse {
  encryptedPin?: string;
  publicKey?: string;
}

function validateAndTrimPin(rawPin: string): string | null {
  // Remove spaces
  const trimmedPin = rawPin.replace(/\s+/g, '');

  // Check if it's a 4-digit number
  const isFourDigitNumber = /^[0-9]{4}$/.test(trimmedPin);

  if (isFourDigitNumber) {
    return trimmedPin;
  } else {
    console.error("The PIN must be a 4-digit number.");
    return null;
  }
}

export class ServerManager {

  static async postShagaPin(rawDecryptedPin: string): Promise<void> {
    const validatedPin = validateAndTrimPin(rawDecryptedPin);

    if (validatedPin === null) {
      console.error("Invalid PIN format. Aborting POST request.");
      return;
    }

    try {
      const apiUrl = `${API_BASE_URL}/shagaPIN`;
      const response = await fetch(apiUrl, {
        method: 'POST',
        body: JSON.stringify({ decryptedPin: validatedPin }),
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        const data = await response.text();  // Reading response as text instead of JSON
        console.log("Received response from /shagaPIN:", data);
      } else {
        console.error("Failed to post data to /shagaPIN");
      }
    } catch (error) {
      console.error("Error posting data to /shagaPIN:", error);
    }
  }


  static async pollForPin() {
    // If there was a rental active, poll Solana RPC until the rental is not active anymore
    if (sharedState.wasRentalActive) {
      await checkRentalState();
      return;
    }
    // If there was no rental active, proceed with the original polling mechanism
    if (!sharedState.isAffairInitiated) {
      console.log("Affair not initiated. Stopping polling.");
      return;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/checkForPair`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      if (response.ok) {
        // Update this line to expect two types of public keys
        const data: { encryptedPin: string, EdPublicKey : string, XPublicKey: string } = await response.json();
        // Update this condition to check for both public keys
        if (data.encryptedPin && data.EdPublicKey  && data.XPublicKey) {
          // Update this function call to include both public keys
          const error = await decryptPINAndVerifyPayment(data.encryptedPin, data.EdPublicKey, data.XPublicKey);

          if (error) {
            console.error('Error during decryption or payment verification:', error);
          }
          return;
        } else {
          console.log("Data not yet ready");
        }
      } else {
        console.error("Failed to fetch data from /checkForPair");
      }
    } catch (error) {
      console.error("Error fetching data from /checkForPair:", error);
    }
  }

  static async unpairAllClients() { // TODO: MOVE LOGIC TO C++ BACKEND
    try {
      const response = await fetch(`${API_BASE_URL}/clients/unpair`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      if (response.ok) {
        console.log('Successfully unpaired all clients.');
      } else {
        console.log('Failed to unpair clients.');
      }
    } catch (error) {
      console.error(`Error while unpairing clients: ${error}`);
    }
  }

  static async backupSharedStateToBackend(): Promise<void> { // TODO: MOVE LOGIC TO C++ BACKEND
    try {
      // Destructure to separate sharedKeypair and get the "safe" part of the state
      const { sharedKeypair, ...safeSharedState } = sharedState;

      // Type assertion to make sure safeSharedState matches SafeSharedStateType
      const payload: SafeSharedStateType = safeSharedState;

      // POST request to backup the "safe" part of the state
      const response = await fetch(`${API_BASE_URL}/backupSharedState`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      // Log success or failure
      if (response.ok) {
        console.log('Successfully backed up sharedState to the backend.');
      } else {
        console.log('Failed to backup sharedState to the backend.');
      }
    } catch (error) {
      console.error(`Error while backing up sharedState: ${error}`);
    }
  }

  static async loadSharedStateFromBackend(): Promise<void> {
    try {
      const response = await fetch(`${API_BASE_URL}/loadSharedState`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        const loadedState = await response.json(); // Don't cast here; we'll validate each field individually
        if ('isRentPaid' in loadedState) {
          sharedState.isRentPaid = loadedState.isRentPaid;
        }
        if ('isEncryptedPinReceived' in loadedState) {
          sharedState.isEncryptedPinReceived = loadedState.isEncryptedPinReceived;
        }
        if ('affairAccountPublicKey' in loadedState) {
          sharedState.affairAccountPublicKey = loadedState.affairAccountPublicKey;
        }
        if ('isAffairInitiated' in loadedState) {
          sharedState.isAffairInitiated = loadedState.isAffairInitiated;
        }
        if ('wasRentalActive' in loadedState) {
          sharedState.wasRentalActive = loadedState.wasRentalActive;
        }
        console.log('Successfully loaded sharedState from the backend.');
      } else {
        console.log('Failed to load sharedState from the backend.');
      }
    } catch (error) {
      console.error(`Error while loading sharedState: ${error}`);
    }
  }


  static async postEncryptedMnemonicToServer(encrypted: string | Uint8Array): Promise<boolean> {
    try {
      // Convert encrypted to string based on its type
      const encryptedStr = (typeof encrypted === "string") ? encrypted : encrypted.toString();

      const response = await fetch(`${API_BASE_URL}/store_mnemonic`, {
        method: 'POST',
        body: JSON.stringify({ encrypted: encryptedStr }),
        headers: { 'Content-Type': 'application/json' },
      });

      return response.ok;
    } catch (error) {
      console.error('Error:', error);
      return false;
    }
  }



  // Function to load encrypted keypair from server
  static async loadEncryptedKeypairFromServer(): Promise<EncryptResult | null> {
    try {
      const response =  await fetch(`${API_BASE_URL}/fetch_keypair`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        const data = await response.json();
        // Decode the Base64 strings to Uint8Array
        const encrypted = Uint8Array.from(Buffer.from(data.encrypted, 'base64'));
        const nonce = Uint8Array.from(Buffer.from(data.nonce, 'base64'));
        const salt = Uint8Array.from(Buffer.from(data.salt, 'base64'));

        return {
          encrypted: encrypted,
          nonce: nonce,
          salt: salt,
        };
      }
    } catch (error) {
      console.error('Error:', error);
    }
    return null;
  }

  static async postEncryptedKeypairToServer(encryptedKeypair: EncryptResult): Promise<boolean> {
    try {
      const encryptedBase64 = Buffer.from(encryptedKeypair.encrypted).toString('base64');
      const nonceBase64 = Buffer.from(encryptedKeypair.nonce).toString('base64');
      const saltBase64 = Buffer.from(encryptedKeypair.salt).toString('base64');

      const response = await fetch(`${API_BASE_URL}/store_keypair`, {
        method: 'POST',
        body: JSON.stringify({
          encrypted: encryptedBase64,
          nonce: nonceBase64,
          salt: saltBase64,
        }),
        headers: { 'Content-Type': 'application/json' },
      });

      if (response.ok) {
        return true;
      } else {
        console.error(`Server responded with status: ${response.status}`);
        const text = await response.text();
        console.error(`Server response body: ${text}`);
        return false;
      }
    } catch (error) {
      console.error('Error:', error);
      return false;
    }
  }
}

export async function fetchSystemInfo(): Promise<SystemInfo | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/system_info`);
    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch (error) {
    console.error('Error:', error);
    return null;
  }
}
