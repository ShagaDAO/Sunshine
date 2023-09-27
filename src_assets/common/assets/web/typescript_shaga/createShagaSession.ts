import WebSocket from 'ws';
import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import bs58 from 'bs58';
import { EncryptionManager, EncryptResult } from "./encryptionManager";
import { verifyPassword } from './createWallet';
import { sharedState } from './sharedState';
import { fetchSystemInfo } from "./serverManager";
import { createSolanaSessionAccount } from './solanaSession';


const app = express();
app.use(bodyParser.json());


// Initialize WebSocket and connect to Solana RPC
const websocket = new WebSocket('ws://localhost:8900'); // Replace with actual Solana RPC address

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
      sharedState.isRentPaid = true;
    }
  }
});


// Function to load encrypted keypair from server
async function loadEncryptedKeypairFromServer(): Promise<EncryptResult | null> {
  try {
    const response = await fetch(`[Server's Backend URL]/get_keypair`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    if (response.ok) {
      const data = await response.json();
      return {
        encrypted: new Uint8Array(bs58.decode(data.encrypted)),
        nonce: new Uint8Array(bs58.decode(data.nonce)),
        salt: new Uint8Array(bs58.decode(data.salt)),
      };
    }
  } catch (error) {
    console.error('Error:', error);
  }
  return null;
}

// Function to listen for payments
function listenForPayments(sessionAccountPublicKey: string) {
  // TODO: Implement WebSocket listening logic here
}

// Initialize
(async () => {
  const userPassword = prompt("Please enter your password:");  // Obtain password from user
  if (userPassword === null) {
    console.error('Password prompt cancelled.');
    return;
  }

  // Verify the user's password using the imported function
  const isVerified = await verifyPassword(userPassword);
  if (!isVerified) {
    console.error('Password verification failed.');
    return;
  }

  const systemInfo = await fetchSystemInfo();
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
  const sessionAccountPublicKey = await createSolanaSessionAccount(payload);

  const encryptedKeypair = await loadEncryptedKeypairFromServer();

  if (encryptedKeypair) {
    const decryptedKeypair = await EncryptionManager.decryptED25519Keypair(
      encryptedKeypair,
      userPassword,
      encryptedKeypair.salt
    );
    sharedState.sharedPrivateKey = decryptedKeypair.ed25519PrivateKey;
  }
  listenForPayments(sessionAccountPublicKey);
})();


// Listen for WebSocket messages (Newly added section)
websocket.on('message', (data) => {
  const message = JSON.parse(data.toString());
  if (message.method && message.method === 'accountNotification') {
    const params = message.params;
    const result = params.result;
    const value = result.value;

    // Your logic to check if the payment is received
    if (value.lamports > 1000) { // Replace with your actual condition
      sharedState.isRentPaid = true;
    }
  }
});
app.listen(3001, () => {
  console.log('Server running on http://localhost:3001/');
});