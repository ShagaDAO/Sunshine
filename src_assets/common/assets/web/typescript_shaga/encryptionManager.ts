// encryptionManager.ts

import { Keypair } from '@solana/web3.js';
import * as naclUtil from 'tweetnacl-util';
import * as crypto from 'crypto';
import CryptoJS from 'crypto-js';
import * as nacl from 'tweetnacl';


export interface EncryptResult {
  encrypted: Uint8Array;
  nonce: Uint8Array;
  salt: Uint8Array;
  keyPair?: nacl.BoxKeyPair;
}



export class EncryptionManager {
  static hashPasswordAndSalt(password: string, salt: Uint8Array): string {
    const concatenated = password + salt.toString();
    const hash = CryptoJS.SHA256(concatenated);
    const hexHash = hash.toString(CryptoJS.enc.Hex);
    return hexHash;
  }

  static async deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const effectiveSalt = salt || nacl.randomBytes(16);
    const hashedPassword = this.hashPasswordAndSalt(password, effectiveSalt);
    const input = new TextEncoder().encode(hashedPassword + effectiveSalt.toString());
    const derivedKey = nacl.hash(input).subarray(0, nacl.secretbox.keyLength);
    return derivedKey;
  }

  static async mapEd25519ToX25519(ed25519PrivateKey: Uint8Array, ed25519PublicKey: Uint8Array): Promise<nacl.BoxKeyPair> {
    // Use tweetnacl's box.keyPair.fromSecretKey to map ed25519 to x25519
    const x25519KeyPair = nacl.box.keyPair.fromSecretKey(ed25519PrivateKey);
    return x25519KeyPair;
  }

  static async decryptPinWithX25519PublicKey(encryptedPin: Uint8Array, x25519PrivateKey: Uint8Array, x25519ClientPublicKey: Uint8Array): Promise<string> {
    // Generate the shared secret using nacl.scalarMult
    const sharedSecret = nacl.scalarMult(x25519PrivateKey, x25519ClientPublicKey);
    const aesKey = sharedSecret.slice(0, 16);
    return this.decryptAES(aesKey, encryptedPin);
  }

  static decryptAES(key: Uint8Array, encryptedData: Uint8Array): string {
    const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key), null);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(Buffer.from(encryptedData));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  }

  static async encryptED25519Keypair(keypair: { ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    const effectiveSalt = salt || nacl.randomBytes(16);
    const key = await this.deriveKey(password, effectiveSalt);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.secretbox(keypair.ed25519PrivateKey, nonce, key);
    return { encrypted, nonce, salt: effectiveSalt };
  }

  static async decryptED25519Keypair(encryptedKeypair: EncryptResult, password: string, salt: Uint8Array): Promise<{ ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }> {
    const key = await this.deriveKey(password, salt);
    const decrypted = nacl.secretbox.open(encryptedKeypair.encrypted, encryptedKeypair.nonce, key);
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
    const decrypted = nacl.secretbox.open(encrypted, nonce, key);  // Now encrypted and nonce are defined
    return decrypted ? naclUtil.encodeUTF8(new Uint8Array(decrypted)) : null;
  }
}