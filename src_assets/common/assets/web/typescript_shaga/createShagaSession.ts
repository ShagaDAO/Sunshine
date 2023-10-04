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
const websocket = new WebSocket('ws://localhost:8900'); // TODO: Replace with actual Solana RPC address

function subscribeToAccount(accountPublicKey: string) {
  websocket.on('open', () => {
    const subscribeParams = {
      jsonrpc: "2.0",
      id: 1,
      method: "accountSubscribe",
      params: [
        accountPublicKey,
        {
          encoding: "jsonParsed",
          commitment: "finalized"
        }
      ]
    };
    websocket.send(JSON.stringify(subscribeParams));
  });
}




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
  // Listen for WebSocket messages
  websocket.on('message', (data) => {
    const message = JSON.parse(data.toString());
    if (message.method && message.method === 'accountNotification') {
      const params = message.params;
      const result = params.result;
      const value = result.value;

      if (value.lamports > 1000) { // TODO: Replace with actual condition
        sharedState.isRentPaid = true;
      }
    }
  });
}

// Initialize
(async () => {
  let userPassword = null;
  let isVerified = false;
  let systemInfo = null;
  let parsedUsdcPerHour = NaN;
  let parsedLendingDuration = NaN;

  // Password Verification Loop
  while (!isVerified) {
    try {
      userPassword = prompt("Please enter your password:");
      if (userPassword === null) {
        console.error('Password prompt cancelled.');
        return;
      }
      isVerified = await verifyPassword(userPassword);
      if (!isVerified) {
        console.error('Password verification failed. Please try again.');
      }
    } catch (e) {
      console.error('An error occurred during password verification. Please try again.');
    }
  }

  // Fetch System Info
  systemInfo = await fetchSystemInfo();
  if (!systemInfo) {
    console.error('Failed to fetch system info.');
    return;
  }

  // USDC Rate Loop
  while (isNaN(parsedUsdcPerHour)) {
    try {
      const usdcPerHour = prompt("Please enter how many USDC per hour you require:");
      if (usdcPerHour === null) {
        console.error('USDC rate prompt cancelled.');
        return;
      }
      parsedUsdcPerHour = parseFloat(usdcPerHour);
      if (isNaN(parsedUsdcPerHour)) {
        console.error('Invalid USDC rate entered. Please enter a valid number.');
      }
    } catch (e) {
      console.error('An error occurred during USDC rate input. Please try again.');
    }
  }

  // Lending Duration Loop
  while (isNaN(parsedLendingDuration)) {
    try {
      const lendingDuration = prompt("Please enter how many hours you plan to lend:");
      if (lendingDuration === null) {
        console.error('Lending duration prompt cancelled.');
        return;
      }
      parsedLendingDuration = parseFloat(lendingDuration);
      if (isNaN(parsedLendingDuration)) {
        console.error('Invalid lending duration entered. Please enter a valid number.');
      }
    } catch (e) {
      console.error('An error occurred during lending duration input. Please try again.');
    }
  }

  // Calculate affairTerminationTime (current Unix timestamp + lending duration in seconds)
  const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
  const affairTerminationTime = currentTime + (parsedLendingDuration * 3600);

  // Prepare payload
  const payload = {
    systemInfo,
    usdcPerHour: parsedUsdcPerHour,
    affairTerminationTime
  };

  // Create session account on Solana
  const sessionAccountPublicKey = await createSolanaSessionAccount(payload);

  const encryptedKeypair = await loadEncryptedKeypairFromServer();

  if (encryptedKeypair && userPassword!= null) {
    const decryptedKeypair = await EncryptionManager.decryptED25519Keypair(
      encryptedKeypair,
      userPassword,
      encryptedKeypair.salt
    );
    sharedState.sharedPrivateKey = decryptedKeypair.ed25519PrivateKey;
  }
  listenForPayments(sessionAccountPublicKey);
})();

app.listen(3001, () => {
  console.log('Server running on http://localhost:3001/');
});