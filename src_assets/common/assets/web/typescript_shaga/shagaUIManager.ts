// shagaUIManager.ts

import { connection, ServerManager } from "./serverManager";
import { createWallet } from "./createWallet";
import { initiatePollingLoop, startAffair } from "./initializeAffair";
import { checkRentalState, terminateAffairButton } from "./shagaTransactions";
import  { sharedState } from "./sharedState";
import { Keypair, PublicKey } from "@solana/web3.js";
import { EncryptionManager } from "./encryptionManager";
import * as QRCode from 'qrcode';

(window as any).Buffer = (window as any).Buffer || require('buffer').Buffer;

export const messageDisplay = document.getElementById('messageDisplay') as HTMLElement;

let qrCodeDisplayed = false;

//Pairing string displayer
export async function displayPairingString(pairingString: string): Promise<void> {
  const pairingStringElement = document.getElementById('pairingStringText') as HTMLElement;

  if (!pairingStringElement) {
    console.error('Pairing String element not found.');
    return;
  }

  pairingStringElement.textContent = pairingString;
}

// Update UI Indicators based on sharedState
export async function updateUIIndicators() {
  await checkRentalState();

  const affairIndicator = document.getElementById("affairIndicator") as HTMLElement;
  const rentalIndicator = document.getElementById("rentalIndicator") as HTMLElement;

  if (!affairIndicator || !rentalIndicator) {
    console.error('Affair and/or Rental Indicator HTML elements not found.');
    return;
  }

  if (sharedState.isAffairInitiated) {
    affairIndicator.textContent = "Affair is Active";
    affairIndicator.classList.remove("bg-warning");
    affairIndicator.classList.add("bg-success");
  } else {
    affairIndicator.textContent = "No Active Affair";
    affairIndicator.classList.remove("bg-success");
    affairIndicator.classList.add("bg-warning");
  }

  if (sharedState.wasRentalActive) {
    rentalIndicator.textContent = "Rental is Active";
    rentalIndicator.classList.remove("bg-warning");
    rentalIndicator.classList.add("bg-success");
  } else {
    rentalIndicator.textContent = "No Active Rental";
    rentalIndicator.classList.remove("bg-success");
    rentalIndicator.classList.add("bg-warning");
  }
}

export function initializeShagaUI(walletExists: boolean, passwordEnteredSuccessfully: boolean) {

  const startShagaSessionBtn = document.getElementById('startShagaSessionBtn') as HTMLButtonElement;
  const createWalletBtn = document.getElementById('createWalletBtn') as HTMLButtonElement;
  const terminateSessionBtn = document.getElementById('terminateSessionBtn') as HTMLButtonElement;
  const systemInfoDisplay = document.getElementById('systemInfoDisplay') as HTMLElement;

  fetchAndDisplayBalance();
  updateUIIndicators();

  if (!startShagaSessionBtn || !createWalletBtn || !systemInfoDisplay || !messageDisplay) {
    console.error('Essential HTML elements not found.');
    return;
  }

  // Terminate session
  terminateSessionBtn.addEventListener('click', async () => {
    try {
      await terminateAffairButton();
      updateUIIndicators();
    } catch (error) {
      console.error('Failed to terminate Shaga session:', error);
    }
  });

  // Start Shaga session
  if (startShagaSessionBtn) {
    startShagaSessionBtn.addEventListener('click', async () => {
      try {
        await startAffair();
        updateUIIndicators();
      } catch (error) {
        console.error('Failed to start Shaga session:', error);
      }
    });
  }

  async function createWalletHandler() {
    messageDisplay.className = 'alert alert-info';
    messageDisplay.innerHTML = 'Creating wallet...';
    try {
      await createWallet();
      walletExists = true;
      createWalletBtn.removeEventListener('click', createWalletHandler);
      createWalletBtn.addEventListener('click', generateQRCode);
      createWalletBtn.innerHTML = 'QR Code Deposit';
    } catch (error) {
      console.error('Failed to create wallet:', error);
    }
  }
  // Remove any previous event listeners from createWalletBtn
  createWalletBtn.removeEventListener('click', createWalletHandler);
  createWalletBtn.removeEventListener('click', generateQRCode);

  // Adds the appropriate event listener. This is safe.
  if (walletExists) {
    createWalletBtn.innerHTML = 'QR Code Deposit';
    createWalletBtn.removeEventListener('click', createWalletHandler);
    createWalletBtn.addEventListener('click', generateQRCode);
  } else {
    createWalletBtn.innerHTML = 'Create Wallet';
    createWalletBtn.removeEventListener('click', generateQRCode);
    createWalletBtn.addEventListener('click', createWalletHandler);
  }
}

async function generateQRCode() {
  const targetDiv = document.getElementById('qrCodeDiv');
  // Check if the shared keypair is available; if not, load and decrypt it
  if (!sharedState.sharedKeypair) {
    try {
      await loadAndDecryptKeypair();
    } catch (error) {
      console.error('Failed to load and decrypt keypair:', error);
      return;
    }
  }
  // Fetch and display the balance regardless of whether the QR code is displayed or not
  await fetchAndDisplayBalance();

  if (qrCodeDisplayed) {
    // Already displaying a QR code, so let's hide it and refresh the balance
    const existingCanvas = document.getElementById('qrcode-canvas');
    existingCanvas?.remove();
    qrCodeDisplayed = false;  // Reset the flag
  } else {
    // Generate and display the QR code
    if (sharedState.sharedKeypair) {
      const publicKeyBase58 = (sharedState.sharedKeypair.publicKey).toBase58();  // Convert to base58 string
      // Create canvas element
      const canvas = document.createElement('canvas');
      canvas.id = 'qrcode-canvas';
      // Generate QR code and append to target div
      try {
        await QRCode.toCanvas(canvas, publicKeyBase58);
        targetDiv?.appendChild(canvas);
        qrCodeDisplayed = true;  // Set the flag
      } catch (error) {
        console.error('Failed to generate QR code:', error);
      }
    } else {
      console.error('No shared keypair found.');
    }
  }
}

export async function loadAndDecryptKeypair(password?: string): Promise<void> {
  // Check if the keypair already exists in sharedState
  if (sharedState.sharedKeypair) {
    console.log("Keypair already exists in sharedState. Skipping load and decrypt.");
    return; // If it does, simply return and skip the rest of the function
  }
  // If the keypair does not exist in sharedState, proceed to load and decrypt
  const encryptedKeypair = await ServerManager.loadEncryptedKeypairFromServer();
  if (encryptedKeypair === null) {
    console.error('Failed to load encrypted keypair.');
    throw new Error('Failed to load encrypted keypair.');
  }

  let decryptedKeypair;
  let attempts = 0;
  const maxAttempts = 5;

  while (attempts < maxAttempts) {
    const pwd = password || prompt("Please enter your password:");
    if (pwd === null) {
      console.error('Password prompt cancelled.');
      throw new Error('Password prompt cancelled.');
    }

    try {
      decryptedKeypair = await EncryptionManager.decryptED25519Keypair(encryptedKeypair, pwd, encryptedKeypair.salt);
      break; // Exit the loop if decryption is successful
    } catch (error) {
      console.error('Decryption failed. Try again.');
      attempts++;
      if (attempts >= maxAttempts) {
        console.error('Max attempts reached. Aborting.');
        throw new Error('Max decryption attempts reached');
      }
    }
  }
  if (decryptedKeypair !== undefined) {
    sharedState.sharedKeypair = Keypair.fromSecretKey(decryptedKeypair.ed25519PrivateKey);
  } else {
    console.error('Failed to decrypt keypair.');
    throw new Error('Failed to decrypt keypair.');
  }
}

export async function fetchAndDisplayBalance() {
  // Initialize UI elements
  const userInfoDiv = document.getElementById('userInfo');
  let balanceDiv = document.getElementById('balanceInfo') as HTMLDivElement;
  const userPublicKeySpan = document.getElementById('userPublicKey');
  // Step 1: Check if the shared keypair exists, if not try to load and decrypt it
  if (!sharedState.sharedKeypair) {
    console.warn('No keypair found in shared state. Attempting to load...');
    try {
      await loadAndDecryptKeypair();
      if (!sharedState.sharedKeypair) {
        console.error('Failed to load and decrypt keypair.');
        return;
      }
    } catch (error) {
      console.error('An error occurred while loading and decrypting the keypair:', error);
      return;
    }
  }
  // Step 1.1: Update the address in the UI
  if (sharedState.sharedKeypair) {
    const publicKeyBase58 = (sharedState.sharedKeypair.publicKey).toBase58();
    if (userPublicKeySpan) {
      userPublicKeySpan.innerText = publicKeyBase58;
    } else {
      console.error('userPublicKey element not found.');
    }
  } else {
    console.error('Keypair is still not available in shared state after attempting to load and decrypt.');
  }
  // Step 2: Continue to fetch and display the balance
  const publicKey = sharedState.sharedKeypair.publicKey;
  // Create the balance display element if it doesn't exist
  if (!balanceDiv) {
    balanceDiv = document.createElement('div');
    balanceDiv.id = 'balanceInfo';
    userInfoDiv?.appendChild(balanceDiv);
  }

  try {
    const balance = await connection.getBalance(publicKey);
    // Convert LAMPORTS to SOL
    const balanceInSOL = balance / 1_000_000_000;
    // Update the balance display
    balanceDiv.innerHTML = `Balance: ${balanceInSOL.toFixed(2)} SOL`;
  } catch (error) {
    console.error('Failed to fetch balance:', error);
  }
}

export async function getWalletStatus(): Promise<boolean> {
  try {
    const response = await fetch('/api/get_wallet_status');
    if (!response.ok) {
      console.error('Failed to fetch wallet status');
      return false;
    }
    const data = await response.text();  // Get the text response
    const cleanedData = data.replace(/"/g, '');
    return cleanedData === "true";  // Convert the cleaned string "true" or "false" to a boolean
  } catch (error) {
    console.error('An error occurred while fetching wallet status:', error);
    return false;
  }
}

// Function to initialize everything
export async function initializeApp(): Promise<void> {
  let passwordEnteredSuccessfully = false;
  try {
    // Get the wallet status
    const walletStatus = await getWalletStatus();
    // Always load the shared state
    await ServerManager.loadSharedStateFromBackend();
    console.log('SharedState has been loaded.');
    isAffairStillActive();
    // If the wallet is active, proceed to load and decrypt the keypair
    if (walletStatus) {
      // Timeout after 10 seconds
      const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('Keypair loading timeout')), 10000));

      try {
        // Wait for either the keypair to load or the timeout to occur
        await Promise.race([
          loadAndDecryptKeypair(),
          timeoutPromise
        ]);
        passwordEnteredSuccessfully = true;
      } catch (error) {
        // Log any errors that occur during the loading of the keypair
        console.error(`An error occurred while loading keypair: ${error}`);
      }
    }
    // Initialize the UI, passing in the wallet status and whether the password was entered successfully
    initializeShagaUI(walletStatus, passwordEnteredSuccessfully);
  } catch (error) {
    console.error(`An error occurred: ${error}`);
  }
}

async function isAffairStillActive(): Promise<void> {
  // sharedState is globally accessible, so you can directly check its properties
  if (sharedState.isAffairInitiated && !sharedState.wasRentalActive) {
    await initiatePollingLoop();
  }
}


// Starting point
document.addEventListener('DOMContentLoaded', async () => {
  initializeApp();
});