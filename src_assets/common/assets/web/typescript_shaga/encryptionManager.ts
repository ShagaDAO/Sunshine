// encryptionManager.ts

import CryptoJS from 'crypto-js';
import * as nacl from "tweetnacl";
import * as naclUtil from "tweetnacl-util";
import _sodium from 'libsodium-wrappers';
import { Keypair } from "@solana/web3.js";

export interface EncryptResult {
  encrypted: Uint8Array | string;
  nonce: Uint8Array;
  salt: Uint8Array;
  keyPair?: nacl.BoxKeyPair;
}

export interface MappedKeys {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export class EncryptionManager {
  static hashPasswordAndSalt(password: string, salt: Uint8Array): string {
    const concatenated = password + salt.toString();
    const hash = CryptoJS.SHA256(concatenated);
    return hash.toString(CryptoJS.enc.Hex);
  }

  static async deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const effectiveSalt = salt || nacl.randomBytes(16);
    const hashedPassword = this.hashPasswordAndSalt(password, effectiveSalt);
    const input = new TextEncoder().encode(hashedPassword + effectiveSalt.toString());
    return nacl.hash(input).subarray(0, nacl.secretbox.keyLength);
  }

  static async hexToBytes(hex: string): Promise<Uint8Array> {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }


  static async deriveAESKey(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    // Wait for libsodium to be ready
    await _sodium.ready;
    const sodium = _sodium;
    // Validate key lengths
    if (privateKey.length !== 32 || publicKey.length !== 32) {
      throw new Error('Invalid key length. Both privateKey and publicKey must be 32 bytes.');
    }
    // Perform the scalar multiplication using libsodium
    const sharedSecret = sodium.crypto_scalarmult(privateKey, publicKey);

    if (!sharedSecret) {
      throw new Error("Failed to derive shared secret");
    }

    return sharedSecret;
  }

  static async decryptPinWithAES(encryptedPin: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array): Promise<string> {
    try {
      // Derive the AES key using your existing method
      const aesKey = await EncryptionManager.deriveAESKey(privateKey, publicKey);
      // Check the AES key length; it should be 32 bytes for AES-256
      if (aesKey.length !== 32) {
        return Promise.reject(new Error("Invalid AES key length."));
      }
      // Convert the derived AES key and encrypted PIN to Base64
      const keyBase64 = Buffer.from(aesKey).toString('base64');
      const encryptedPinBase64 = Buffer.from(encryptedPin).toString('base64');
      // Convert the Base64 AES key and encrypted PIN to CryptoJS's WordArray format
      const keyWordArray = CryptoJS.enc.Base64.parse(keyBase64);
      const encryptedPinWordArray = CryptoJS.enc.Base64.parse(encryptedPinBase64);
      // Perform decryption using AES-ECB mode with PKCS7 padding
      const decryptedData = CryptoJS.AES.decrypt(
        { ciphertext: encryptedPinWordArray } as any,
        keyWordArray,
        {
          mode: CryptoJS.mode.ECB,
          padding: CryptoJS.pad.Pkcs7
        }
      );
      // Convert the decrypted data to a UTF-8 string
      const decryptedPin = CryptoJS.enc.Utf8.stringify(decryptedData);
      console.log(`Decrypted PIN: ${decryptedPin}`);

      return decryptedPin;

    } catch (e) {
      console.error('Error in decryptPinWithAES:', e);
      return Promise.reject(e);
    }
  }



  static async decryptPIN(decodedEncryptedPin: Uint8Array, sharedKeypair: Keypair, clientX25519PublicKey: Uint8Array): Promise<string> {
    try {
      // Wait for libsodium to be ready
      await _sodium.ready;
      const sodium = _sodium;

      console.log('--- Starting decryptPIN Function ---');
      // Get the full 64-byte Ed25519 secret key
      const serverEd25519PrivateKeyFull = sharedKeypair.secretKey;
      // Convert the full 64-byte Ed25519 private key to a 32-byte X25519 private key
      let serverX25519PrivateKey;
      try {
        serverX25519PrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(serverEd25519PrivateKeyFull);
      } catch (e) {
        console.error("Failed to convert Ed25519 private key to X25519:", e);
        throw e;
      }
      // Validate that the resulting X25519 private key is 32 bytes
      if (serverX25519PrivateKey.length !== 32) {
        throw new Error('Invalid X25519 private key length');
      }
      // Decrypt using AES
      return await this.decryptPinWithAES(decodedEncryptedPin, serverX25519PrivateKey, clientX25519PublicKey);
    } catch (e) {
      console.error("--- Error in decryptPIN Function ---");
      console.error("Caught Exception:", e);
      return Promise.reject(e);
    }
  }



  /* TODO: find a better solution for shared state, v2 is moving most of this to the backend.
  static async encryptSharedState(sharedState: any, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    // Step 1: Serialize the sharedState object to a JSON string
    const sharedStateJson = JSON.stringify(sharedState);
    // Step 2: Convert JSON string to Uint8Array
    const sharedStateUint8 = new TextEncoder().encode(sharedStateJson);
    // Step 3: Encrypt the Uint8Array
    const effectiveSalt = salt || nacl.randomBytes(16);
    const key = await this.deriveKey(password, effectiveSalt);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(sharedStateUint8, nonce, key);
    // Convert encrypted, nonce, and salt to Base64
    const encryptedBase64 = Buffer.from(encrypted).toString('base64');
    const nonceBase64 = Buffer.from(nonce).toString('base64');
    const saltBase64 = Buffer.from(effectiveSalt).toString('base64');

    return { encrypted: encryptedBase64, nonce: nonceBase64, salt: saltBase64 };
  }

  static async decryptSharedState(encryptedData: EncryptResult, password: string): Promise<any> {
    // Decode encrypted, nonce, and salt from Base64 to Uint8Array
    const encryptedU8 = Uint8Array.from(Buffer.from(encryptedData.encrypted, 'base64'));
    const nonceU8 = Uint8Array.from(Buffer.from(encryptedData.nonce, 'base64'));
    const saltU8 = Uint8Array.from(Buffer.from(encryptedData.salt, 'base64'));
    // Derive key
    const key = await this.deriveKey(password, saltU8);
    // Decrypt
    const decrypted = nacl.secretbox.open(encryptedU8, nonceU8, key);
    if (!decrypted) {
      throw new Error("Decryption failed");
    }
    // Convert Uint8Array back to JSON string and parse it
    const decryptedJson = new TextDecoder().decode(new Uint8Array(decrypted));
    return JSON.parse(decryptedJson);
  }
   */

  static async encryptED25519Keypair(keypair: { ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    const effectiveSalt = salt || nacl.randomBytes(16);
    const key = await this.deriveKey(password, effectiveSalt);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(keypair.ed25519PrivateKey, nonce, key);
    return { encrypted, nonce, salt: effectiveSalt };
  }

  static async decryptED25519Keypair(encryptedKeypair: EncryptResult, password: string, salt: Uint8Array): Promise<{ ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }> {
    const key = await this.deriveKey(password, salt);
    const decrypted = nacl.secretbox.open(<Uint8Array>encryptedKeypair.encrypted, encryptedKeypair.nonce, key);
    if (!decrypted) throw new Error("Decryption failed");
    const ed25519PrivateKey = new Uint8Array(decrypted);
    const ed25519PublicKey = ed25519PrivateKey.slice(32);
    return { ed25519PublicKey, ed25519PrivateKey };
  }

  static async encryptMnemonic(mnemonic: string, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    const effectiveSalt = salt || nacl.randomBytes(16); // Changed this to 16 bytes
    const key = await this.deriveKey(password, effectiveSalt);
    const nonce = nacl.randomBytes(24); // Changed this to 24 bytes
    const mnemonicUint8 = naclUtil.decodeUTF8(mnemonic);
    const encrypted = nacl.secretbox(mnemonicUint8, nonce, key); // Changed to nacl.secretbox
    return { encrypted, nonce, salt: effectiveSalt };
  }

  static async decryptMnemonic(encryptedData: EncryptResult, password: string): Promise<string | null> {
    const { salt, encrypted, nonce } = encryptedData;  // Destructure variables from encryptedData
    const key = await this.deriveKey(password, salt);  // Now salt is defined
    const decrypted = nacl.secretbox.open(<Uint8Array>encrypted, nonce, key);  // Now encrypted and nonce are defined
    return decrypted ? naclUtil.encodeUTF8(new Uint8Array(decrypted)) : null;
  }
}