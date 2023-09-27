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
exports.createSolanaSessionAccount = void 0;
const borsh_1 = require("@dao-xyz/borsh");
class SessionPayloadSchema {
    constructor(data) {
        this.ipAddress = '';
        this.cpuName = '';
        this.gpuName = '';
        this.totalRamMB = 0;
        this.usdcPerHour = 0;
        Object.assign(this, data);
    }
}
// Validate the class
(0, borsh_1.validate)([SessionPayloadSchema]);
function createSolanaSessionAccount(payload) {
    return __awaiter(this, void 0, void 0, function* () {
        const { systemInfo, usdcPerHour } = payload;
        // Create a new SessionPayloadSchema object
        const sessionPayload = new SessionPayloadSchema({
            ipAddress: systemInfo.ipAddress,
            cpuName: systemInfo.cpuName,
            gpuName: systemInfo.gpuName,
            totalRamMB: systemInfo.totalRamMB,
            usdcPerHour
        });
        // Serialize the payload using BORSH
        const serializedPayload = (0, borsh_1.serialize)(sessionPayload);
        // TODO: Make the RPC call to Solana program to create the session account
        // and return the session public key.
        return 'somePublicKey'; // Placeholder, you'll replace this with the actual public key
    });
}
exports.createSolanaSessionAccount = createSolanaSessionAccount;
