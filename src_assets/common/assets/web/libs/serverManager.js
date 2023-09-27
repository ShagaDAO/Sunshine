"use strict";
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
exports.SolanaManager = exports.fetchSystemInfo = exports.ServerManager = void 0;
const web3_js_1 = require("@solana/web3.js");
const API_BASE_URL = 'https://localhost:47990/api';
const SOLANA_NETWORK = 'https://api.devnet.solana.com'; // Replace with the correct URL
const connection = new web3_js_1.Connection(SOLANA_NETWORK);
class ServerManager {
    static postEncryptedMnemonicToServer(encrypted) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const response = yield fetch(`${API_BASE_URL}/store_mnemonic`, {
                    method: 'POST',
                    body: JSON.stringify({ encrypted: encrypted.toString() }),
                    headers: { 'Content-Type': 'application/json' },
                });
                return response.ok;
            }
            catch (error) {
                console.error('Error:', error);
                return false;
            }
        });
    }
    static postEncryptedKeypairToServer(encryptedKeypair) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const response = yield fetch(`${API_BASE_URL}/store_keypair`, {
                    method: 'POST',
                    body: JSON.stringify({ encryptedKeypair: encryptedKeypair.toString() }),
                    headers: { 'Content-Type': 'application/json' },
                });
                return response.ok;
            }
            catch (error) {
                console.error('Error:', error);
                return false;
            }
        });
    }
}
exports.ServerManager = ServerManager;
function fetchSystemInfo() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const response = yield fetch(`${API_BASE_URL}/system_info`);
            if (response.ok) {
                return yield response.json();
            }
            return null;
        }
        catch (error) {
            console.error('Error:', error);
            return null;
        }
    });
}
exports.fetchSystemInfo = fetchSystemInfo;
class SolanaManager {
    static getBalance(publicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const balance = yield connection.getBalance(publicKey);
                return balance;
            }
            catch (error) {
                console.error('Error fetching balance:', error);
                return null;
            }
        });
    }
}
exports.SolanaManager = SolanaManager;
