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
exports.initializeApp = exports.initializeShagaUI = exports.messageDisplay = void 0;
const createWallet_1 = require("./createWallet");
const serverManager_1 = require("./serverManager");
exports.messageDisplay = document.getElementById('messageDisplay');
function initializeShagaUI() {
    const fetchInfoBtn = document.getElementById('fetchInfoBtn');
    const createWalletBtn = document.getElementById('createWalletBtn');
    const systemInfoDisplay = document.getElementById('systemInfoDisplay');
    if (!fetchInfoBtn || !createWalletBtn || !systemInfoDisplay || !exports.messageDisplay) {
        console.error('Essential HTML elements not found.');
        return;
    }
    // Attaching event listeners
    fetchInfoBtn.addEventListener('click', () => __awaiter(this, void 0, void 0, function* () {
        try {
            const systemInfo = yield (0, serverManager_1.fetchSystemInfo)();
            if (systemInfo) {
                systemInfoDisplay.innerHTML = `
          IP Address: ${systemInfo.ipAddress}<br>
          CPU Name: ${systemInfo.cpuName}<br>
          GPU Name: ${systemInfo.gpuName}<br>
          Total RAM: ${systemInfo.totalRamMB} MB
        `;
            }
            else {
                systemInfoDisplay.innerHTML = 'Failed to fetch system information.';
            }
        }
        catch (error) {
            console.error('Failed to fetch system info:', error);
            systemInfoDisplay.innerHTML = 'An error occurred while fetching system information.';
        }
    }));
    createWalletBtn.addEventListener('click', () => __awaiter(this, void 0, void 0, function* () {
        exports.messageDisplay.className = 'alert alert-info';
        exports.messageDisplay.innerHTML = 'Creating wallet...';
        try {
            yield (0, createWallet_1.createWallet)();
        }
        catch (error) {
            console.error('Failed to create wallet:', error);
        }
    }));
}
exports.initializeShagaUI = initializeShagaUI;
// Function to initialize everything
function initializeApp() {
    initializeShagaUI(); // Set up the initial UI
    //TODO: add balance & earnings graphs fetching data from solana
}
exports.initializeApp = initializeApp;
// Starting point
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});
