// encryptionManager.ts

import CryptoJS from "crypto-js";
import * as nacl from "tweetnacl";
import * as naclUtil from "tweetnacl-util";
import * as sodium from "libsodium-wrappers";


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

  static async mapPublicEd25519ToX25519(ed25519PublicKey: Uint8Array): Promise<Uint8Array> {
    await sodium.ready;
    return sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKey);
  }

  static async mapSecretEd25519ToX25519(ed25519PrivateKey: Uint8Array): Promise<Uint8Array> {
    await sodium.ready;
    return sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519PrivateKey);
  }

  static async hexToBytes(hex: string): Promise<Uint8Array> {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  static async decryptPinWithAES(encryptedPin: Uint8Array, privateKey: Uint8Array, publicKey: Uint8Array): Promise<string> {
    await sodium.ready;
    const sharedSecret = sodium.crypto_scalarmult(privateKey, publicKey);
    const aesKey = sharedSecret.slice(0, 16);
    const key = await window.crypto.subtle.importKey('raw', aesKey.buffer, 'AES-ECB', false, ['decrypt']);
    const decryptedData = await window.crypto.subtle.decrypt({ name: 'AES-ECB' }, key, encryptedPin); // uses PKCS#7 padding
    return new TextDecoder().decode(new Uint8Array(decryptedData));
  }

  static async decryptAndRetrievePIN(decodedEncryptedPin: Uint8Array, receivedEd25519PublicKey: Uint8Array, serverEd25519PrivateKey: Uint8Array): Promise<string> {
    const x25519PublicKey = await this.mapPublicEd25519ToX25519(receivedEd25519PublicKey);
    const x25519PrivateKey = await this.mapSecretEd25519ToX25519(serverEd25519PrivateKey);

    return await this.decryptPinWithAES(decodedEncryptedPin, x25519PrivateKey, x25519PublicKey);
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