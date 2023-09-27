import { Keypair } from '@solana/web3.js';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
import * as sodium from 'libsodium-wrappers';
import * as crypto from 'crypto';
import CryptoJS from 'crypto-js';


export interface EncryptResult {
  encrypted: Uint8Array;
  nonce: Uint8Array;
  salt: Uint8Array;
  keyPair?: nacl.BoxKeyPair;
}



export class EncryptionManager {

  static hashPasswordAndSalt(password: string, salt: Uint8Array): string {
    const concatenated = password + salt.toString();  // Concatenating password and salt
    const hash = CryptoJS.SHA256(concatenated);  // Hashing
    const hexHash = hash.toString(CryptoJS.enc.Hex);  // Converting hash to hex
    return hexHash;
  }

  static async deriveKey(password: string, salt?: Uint8Array): Promise<Uint8Array> {
    await sodium.ready;
    // Generate a new random salt if none is provided
    const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    // Hash password and salt
    const hashedPassword = EncryptionManager.hashPasswordAndSalt(password, effectiveSalt);
    return sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      hashedPassword,
      effectiveSalt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    );
  }


  static async mapEd25519ToX25519(
    ed25519PrivateKey: Uint8Array,
    ed25519PublicKey: Uint8Array
  ): Promise<{ x25519PublicKey: Uint8Array, x25519PrivateKey: Uint8Array }> {
    await sodium.ready;
    const libsodium = sodium;

    const x25519PrivateKey = libsodium.crypto_sign_ed25519_sk_to_curve25519(ed25519PrivateKey);
    const x25519PublicKey = libsodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKey);

    return { x25519PrivateKey, x25519PublicKey };
  }

  static async decryptPinWithX25519PublicKey(encryptedPin: Uint8Array, x25519PrivateKey: Uint8Array, x25519ClientPublicKey: Uint8Array): Promise<string | null> {
    await sodium.ready;
    // Generate the shared secret using the server's private key and the client's public key
    const sharedSecret: Uint8Array = sodium.crypto_scalarmult(x25519PrivateKey, x25519ClientPublicKey);
    // Use the first 16 bytes of the shared secret as the AES key
    const aesKey = sharedSecret.slice(0, 16);
    // Decrypt the AES-encrypted PIN
    return this.decryptAES(aesKey, encryptedPin);
  }

  static decryptAES(key: Uint8Array, encryptedData: Uint8Array): string | null {
    const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key), null);
    decipher.setAutoPadding(true); // This should make it compatible with PKCS5Padding
    let decrypted = decipher.update(Buffer.from(encryptedData));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  }

/* TODO: DECIDE IF WORTH KEEPING X25519 pairs or mapping everytime
  static async encryptX25519Keypair(keypair: { x25519PublicKey: Uint8Array, x25519PrivateKey: Uint8Array }, password: string, salt: Uint8Array): Promise<EncryptResult> {
    const key = await EncryptionManager.deriveKey(password, salt);  // Using the shared function
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const encrypted = sodium.crypto_secretbox_easy(keypair.x25519PrivateKey, nonce, key);
    return { encrypted, nonce, salt };
  }

  static async decryptX25519Keypair(encryptedKeypair: EncryptResult, password: string, salt: Uint8Array): Promise<{ x25519PublicKey: Uint8Array, x25519PrivateKey: Uint8Array }> {
    const key = await EncryptionManager.deriveKey(password, salt);
    const decrypted = sodium.crypto_secretbox_open_easy(encryptedKeypair.encrypted, encryptedKeypair.nonce, key);
    if (!decrypted) {
      throw new Error("Decryption failed");
    }
    const x25519PrivateKey = new Uint8Array(decrypted);
    const x25519PublicKey = sodium.crypto_scalarmult_base(x25519PrivateKey);  // Derive public key from private key
    return { x25519PublicKey, x25519PrivateKey };
  }
 */

  static async encryptED25519Keypair(keypair: { ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = await EncryptionManager.deriveKey(password, effectiveSalt);
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const encrypted = sodium.crypto_secretbox_easy(keypair.ed25519PrivateKey, nonce, key);
    return { encrypted, nonce, salt: effectiveSalt };
  }

// Decrypts an ED25519 keypair
  static async decryptED25519Keypair(encryptedKeypair: EncryptResult, password: string, salt: Uint8Array): Promise<{ ed25519PublicKey: Uint8Array, ed25519PrivateKey: Uint8Array }> {
    const key = await EncryptionManager.deriveKey(password, salt);
    const decrypted = sodium.crypto_secretbox_open_easy(encryptedKeypair.encrypted, encryptedKeypair.nonce, key);
    if (!decrypted) {
      throw new Error("Decryption failed");
    }
    const ed25519PrivateKey = new Uint8Array(decrypted);
    const ed25519PublicKey = ed25519PrivateKey.slice(32);
    return { ed25519PublicKey, ed25519PrivateKey };
  }

// Encrypts a mnemonic
  static async encryptMnemonic(mnemonic: string, password: string, salt?: Uint8Array): Promise<EncryptResult> {
    const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = await EncryptionManager.deriveKey(password, effectiveSalt);
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const mnemonicUint8 = naclUtil.decodeUTF8(mnemonic);
    const encrypted = sodium.crypto_secretbox_easy(mnemonicUint8, nonce, key);
    return { encrypted, nonce, salt: effectiveSalt };
  }

// Decrypts a mnemonic
  static async decryptMnemonic({ encrypted, nonce, salt }: EncryptResult, password: string): Promise<string | null> {
    const key = await EncryptionManager.deriveKey(password, salt);
    const decrypted: Uint8Array | null = sodium.crypto_secretbox_open_easy(encrypted, nonce, key);
    return decrypted ? naclUtil.encodeUTF8(new Uint8Array(decrypted)) : null;
  }
}
