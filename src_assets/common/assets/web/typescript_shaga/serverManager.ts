// serverManager.ts

import { Connection, PublicKey } from '@solana/web3.js';

export const API_BASE_URL = 'https://localhost:47990/api';
export const SOLANA_NETWORK = 'https://api.devnet.solana.com'; // Replace with the correct URL
export let connection = new Connection(SOLANA_NETWORK);


import { SystemInfo } from './shagaUIManager';
import { EncryptResult } from "./encryptionManager";
import bs58 from "bs58";


export class ServerManager {
  static async postEncryptedMnemonicToServer(encrypted: Uint8Array): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE_URL}/store_mnemonic`, {
        method: 'POST',
        body: JSON.stringify({ encrypted: encrypted.toString() }),
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

export async function terminateAffairOnServer(): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}/terminateAffair`, {
      method: 'POST'
    });
    if (!response.ok) {
      throw new Error('Failed to terminate affair on server');
    }
  } catch (error) {
    console.error(`Error in calling terminateAffair endpoint: ${error}`);
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


export class SolanaManager {

  static async getBalance(publicKey: PublicKey): Promise<number | null> {
    try {
      const balance = await connection.getBalance(publicKey);
      return balance;
    } catch (error) {
      console.error('Error fetching balance:', error);
      return null;
    }
  }

}
