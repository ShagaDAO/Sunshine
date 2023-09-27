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
Object.defineProperty(exports, "__esModule", { value: true });
exports.createWallet = exports.verifyPassword = void 0;
const bip39 = __importStar(require("bip39"));
const web3_js_1 = require("@solana/web3.js");
const encryptionManager_1 = require("./encryptionManager");
const serverManager_1 = require("./serverManager");
const serverManager_2 = require("./serverManager");
const shagaUIManager_1 = require("./shagaUIManager");
// Mnemonic generation utility
class MnemonicManager {
    generate() {
        return bip39.generateMnemonic();
    }
    generateKeypair(mnemonic) {
        const seed = bip39.mnemonicToSeedSync(mnemonic, "");
        return web3_js_1.Keypair.fromSeed(seed.slice(0, 32));
    }
}
// Centralized error handling
function handleError(error) {
    console.error(error);
    shagaUIManager_1.messageDisplay.className = 'alert alert-danger';
    shagaUIManager_1.messageDisplay.innerHTML = error;
}
// Password verification TODO: refactor in accountUtility.ts
function verifyPassword(password) {
    return __awaiter(this, void 0, void 0, function* () {
        const response = yield fetch('/api/verify_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        return response.status === 200;
    });
}
exports.verifyPassword = verifyPassword;
// The main createWallet function
function createWallet() {
    return __awaiter(this, void 0, void 0, function* () {
        const reEnteredPassword = prompt("Please re-enter your password:");
        if (reEnteredPassword === null) {
            handleError('Password prompt cancelled.');
            return;
        }
        // Password verification
        const isVerified = yield verifyPassword(reEnteredPassword);
        if (isVerified) {
            shagaUIManager_1.messageDisplay.innerHTML = "Password verified, creating wallet...";
            const mnemonicManager = new MnemonicManager();
            const mnemonic = mnemonicManager.generate();
            const keypair = mnemonicManager.generateKeypair(mnemonic);
            // Generate Keypair and public key
            const renamedKeypair = {
                ed25519PublicKey: keypair.publicKey.toBuffer(),
                ed25519PrivateKey: keypair.secretKey, // Already Uint8Array
            };
            const encryptedKeypair = yield encryptionManager_1.EncryptionManager.encryptED25519Keypair(renamedKeypair, reEnteredPassword);
            // Check if the encryption was successful
            if (encryptedKeypair === null) {
                handleError("Keypair encryption failed!");
                return;
            }
            const encryptionResult = yield encryptionManager_1.EncryptionManager.encryptMnemonic(mnemonic, reEnteredPassword);
            const decryptedMnemonic = encryptionManager_1.EncryptionManager.decryptMnemonic(encryptionResult, reEnteredPassword);
            if (decryptedMnemonic === null) {
                handleError("Decryption failed!");
                return;
            }
            console.log(`Wallet Created. Public Key: ${keypair.publicKey}`);
            // Fetch and display the balance of the new wallet
            const balance = yield serverManager_2.SolanaManager.getBalance(keypair.publicKey);
            if (balance !== null) {
                console.log(`Initial Wallet Balance: ${balance} LAMPORTS`);
            }
            else {
                console.log("Failed to fetch wallet balance.");
            }
            // Store the encrypted mnemonic and keypair
            yield serverManager_1.ServerManager.postEncryptedMnemonicToServer(encryptionResult.encrypted);
            yield serverManager_1.ServerManager.postEncryptedKeypairToServer(encryptedKeypair);
            // After successful wallet creation
            shagaUIManager_1.messageDisplay.className = 'alert alert-success';
            shagaUIManager_1.messageDisplay.innerHTML = `Wallet Created. Public Key: ${keypair.publicKey}`;
        }
        else {
            shagaUIManager_1.messageDisplay.innerHTML = "Invalid password.";
            handleError('Invalid password.');
        }
    });
}
exports.createWallet = createWallet;
