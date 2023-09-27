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
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const encryptionManager_1 = require("./encryptionManager");
const bs58_1 = __importDefault(require("bs58"));
const sharedState_1 = require("./sharedState");
const app = (0, express_1.default)();
app.use(body_parser_1.default.json());
app.post('/endpoint', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    sharedState_1.sharedState.isEncryptedPinReceived = true;
    if (!sharedState_1.sharedState.isRentPaid) {
        res.status(402).json({ error: 'Payment required' });
        return;
    }
    if (sharedState_1.sharedState.sharedPrivateKey === null) {
        res.status(500).json({ error: 'Server private key not loaded' });
        return;
    }
    const { encryptedPIN, publicKey } = req.body;
    const clientPublicKey = new Uint8Array(bs58_1.default.decode(publicKey));
    // Map the decrypted ed25519 private key to its x25519 equivalent
    const mappedKeys = yield encryptionManager_1.EncryptionManager.mapEd25519ToX25519(sharedState_1.sharedState.sharedPrivateKey, clientPublicKey);
    const decryptedPIN = yield encryptionManager_1.EncryptionManager.decryptPinWithX25519PublicKey(new Uint8Array(Buffer.from(encryptedPIN, 'hex')), mappedKeys.x25519PrivateKey, mappedKeys.x25519PublicKey);
    res.json({ decryptedPin: decryptedPIN });
}));
app.listen(3000, () => {
    console.log('Decryption server running on http://localhost:3000/');
});
