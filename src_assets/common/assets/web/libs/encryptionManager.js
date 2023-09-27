"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EncryptionManager = void 0;
const naclUtil = __importStar(require("tweetnacl-util"));
const sodium = __importStar(require("libsodium-wrappers"));
const crypto = __importStar(require("crypto"));
const crypto_js_1 = __importDefault(require("crypto-js"));
class EncryptionManager {
    static hashPasswordAndSalt(password, salt) {
        const concatenated = password + salt.toString(); // Concatenating password and salt
        const hash = crypto_js_1.default.SHA256(concatenated); // Hashing
        const hexHash = hash.toString(crypto_js_1.default.enc.Hex); // Converting hash to hex
        return hexHash;
    }
    static deriveKey(password, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            yield sodium.ready;
            // Generate a new random salt if none is provided
            const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
            // Hash password and salt
            const hashedPassword = EncryptionManager.hashPasswordAndSalt(password, effectiveSalt);
            return sodium.crypto_pwhash(sodium.crypto_secretbox_KEYBYTES, hashedPassword, effectiveSalt, sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, sodium.crypto_pwhash_ALG_DEFAULT);
        });
    }
    static mapEd25519ToX25519(ed25519PrivateKey, ed25519PublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            yield sodium.ready;
            const libsodium = sodium;
            const x25519PrivateKey = libsodium.crypto_sign_ed25519_sk_to_curve25519(ed25519PrivateKey);
            const x25519PublicKey = libsodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKey);
            return { x25519PrivateKey, x25519PublicKey };
        });
    }
    static decryptPinWithX25519PublicKey(encryptedPin, x25519PrivateKey, x25519ClientPublicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            yield sodium.ready;
            // Generate the shared secret using the server's private key and the client's public key
            const sharedSecret = sodium.crypto_scalarmult(x25519PrivateKey, x25519ClientPublicKey);
            // Use the first 16 bytes of the shared secret as the AES key
            const aesKey = sharedSecret.slice(0, 16);
            // Decrypt the AES-encrypted PIN
            return this.decryptAES(aesKey, encryptedPin);
        });
    }
    static decryptAES(key, encryptedData) {
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
    static encryptED25519Keypair(keypair, password, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
            const key = yield EncryptionManager.deriveKey(password, effectiveSalt);
            const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
            const encrypted = sodium.crypto_secretbox_easy(keypair.ed25519PrivateKey, nonce, key);
            return { encrypted, nonce, salt: effectiveSalt };
        });
    }
    // Decrypts an ED25519 keypair
    static decryptED25519Keypair(encryptedKeypair, password, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield EncryptionManager.deriveKey(password, salt);
            const decrypted = sodium.crypto_secretbox_open_easy(encryptedKeypair.encrypted, encryptedKeypair.nonce, key);
            if (!decrypted) {
                throw new Error("Decryption failed");
            }
            const ed25519PrivateKey = new Uint8Array(decrypted);
            const ed25519PublicKey = ed25519PrivateKey.slice(32);
            return { ed25519PublicKey, ed25519PrivateKey };
        });
    }
    // Encrypts a mnemonic
    static encryptMnemonic(mnemonic, password, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            const effectiveSalt = salt || sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
            const key = yield EncryptionManager.deriveKey(password, effectiveSalt);
            const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
            const mnemonicUint8 = naclUtil.decodeUTF8(mnemonic);
            const encrypted = sodium.crypto_secretbox_easy(mnemonicUint8, nonce, key);
            return { encrypted, nonce, salt: effectiveSalt };
        });
    }
    // Decrypts a mnemonic
    static decryptMnemonic({ encrypted, nonce, salt }, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield EncryptionManager.deriveKey(password, salt);
            const decrypted = sodium.crypto_secretbox_open_easy(encrypted, nonce, key);
            return decrypted ? naclUtil.encodeUTF8(new Uint8Array(decrypted)) : null;
        });
    }
}
exports.EncryptionManager = EncryptionManager;
