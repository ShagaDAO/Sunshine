import { Connection, PublicKey } from '@solana/web3.js';

const API_BASE_URL = 'https://localhost:47990/api';
const SOLANA_NETWORK = 'https://api.devnet.solana.com'; // Replace with the correct URL
const connection = new Connection(SOLANA_NETWORK);


import { SystemInfo } from './shagaUIManager';
import { EncryptResult } from "./encryptionManager";


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

  static async postEncryptedKeypairToServer(encryptedKeypair: EncryptResult): Promise<boolean> {
    try {
      const response = await fetch(`${API_BASE_URL}/store_keypair`, {
        method: 'POST',
        body: JSON.stringify({ encryptedKeypair: encryptedKeypair.toString() }),
        headers: { 'Content-Type': 'application/json' },
      });
      return response.ok;
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
