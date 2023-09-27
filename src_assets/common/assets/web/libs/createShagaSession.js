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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ws_1 = __importDefault(require("ws"));
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const node_fetch_1 = __importDefault(require("node-fetch"));
const bs58_1 = __importDefault(require("bs58"));
const encryptionManager_1 = require("./encryptionManager");
const createWallet_1 = require("./createWallet");
const sharedState_1 = require("./sharedState");
const serverManager_1 = require("./serverManager");
const solanaSession_1 = require("./solanaSession");
const app = (0, express_1.default)();
app.use(body_parser_1.default.json());
// Initialize WebSocket and connect to Solana RPC
const websocket = new ws_1.default('ws://localhost:8900'); // Replace with actual Solana RPC address
// Subscribe to an account to get notifications
websocket.on('open', () => {
    const subscribeParams = {
        jsonrpc: "2.0",
        id: 1,
        method: "accountSubscribe",
        params: [
            // TODO: The public key of the account you're interested in
            "YourAccountPublicKeyHere",
            {
                encoding: "jsonParsed",
                commitment: "finalized"
            }
        ]
    };
    websocket.send(JSON.stringify(subscribeParams));
});
// Listen for WebSocket messages (Newly added section)
websocket.on('message', (data) => {
    const message = JSON.parse(data.toString());
    if (message.method && message.method === 'accountNotification') {
        const params = message.params;
        const result = params.result;
        const value = result.value;
        // Your logic to check if the payment is received
        if (value.lamports > 1000) { // Replace with your actual condition
            sharedState_1.sharedState.isRentPaid = true;
        }
    }
});
// Function to load encrypted keypair from server
function loadEncryptedKeypairFromServer() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const response = yield (0, node_fetch_1.default)(`[Server's Backend URL]/get_keypair`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
            });
            if (response.ok) {
                const data = yield response.json();
                return {
                    encrypted: new Uint8Array(bs58_1.default.decode(data.encrypted)),
                    nonce: new Uint8Array(bs58_1.default.decode(data.nonce)),
                    salt: new Uint8Array(bs58_1.default.decode(data.salt)),
                };
            }
        }
        catch (error) {
            console.error('Error:', error);
        }
        return null;
    });
}
// Function to listen for payments
function listenForPayments(sessionAccountPublicKey) {
    // TODO: Implement WebSocket listening logic here
}
// Initialize
(() => __awaiter(void 0, void 0, void 0, function* () {
    const userPassword = prompt("Please enter your password:"); // Obtain password from user
    if (userPassword === null) {
        console.error('Password prompt cancelled.');
        return;
    }
    // Verify the user's password using the imported function
    const isVerified = yield (0, createWallet_1.verifyPassword)(userPassword);
    if (!isVerified) {
        console.error('Password verification failed.');
        return;
    }
    const systemInfo = yield (0, serverManager_1.fetchSystemInfo)();
    if (!systemInfo) {
        console.error('Failed to fetch system info.');
        return;
    }
    // Ask the user for their required USDC per hour rate
    const usdcPerHour = prompt("Please enter how many USDC per hour you require:");
    if (usdcPerHour === null) {
        console.error('USDC rate prompt cancelled.');
        return;
    }
    // Type check and parsing
    const parsedUsdcPerHour = parseFloat(usdcPerHour);
    if (isNaN(parsedUsdcPerHour)) {
        console.error('Invalid USDC rate entered.');
        return;
    }
    // Prepare payload
    const payload = {
        systemInfo,
        usdcPerHour: parsedUsdcPerHour
    };
    // Create session account on Solana
    const sessionAccountPublicKey = yield (0, solanaSession_1.createSolanaSessionAccount)(payload);
    const encryptedKeypair = yield loadEncryptedKeypairFromServer();
    if (encryptedKeypair) {
        const decryptedKeypair = yield encryptionManager_1.EncryptionManager.decryptED25519Keypair(encryptedKeypair, userPassword, encryptedKeypair.salt);
        sharedState_1.sharedState.sharedPrivateKey = decryptedKeypair.ed25519PrivateKey;
    }
    listenForPayments(sessionAccountPublicKey);
}))();
// Listen for WebSocket messages (Newly added section)
websocket.on('message', (data) => {
    const message = JSON.parse(data.toString());
    if (message.method && message.method === 'accountNotification') {
        const params = message.params;
        const result = params.result;
        const value = result.value;
        // Your logic to check if the payment is received
        if (value.lamports > 1000) { // Replace with your actual condition
            sharedState_1.sharedState.isRentPaid = true;
        }
    }
});
app.listen(3001, () => {
    console.log('Server running on http://localhost:3001/');
});
