// initializeAffair.ts

import { EncryptionManager } from "./encryptionManager";
import { verifyPassword } from "./createWallet";
import { sharedState } from "./sharedState";
import { connection, fetchSystemInfo, ServerManager } from "./serverManager";
import { createShagaAffair, checkIfAffairExists, initializeLenderIfNecessary } from "./shagaTransactions";
import { Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";


export interface SystemInfo {
  coordinates: string;
  ipAddress: string;
  cpuName: string;
  gpuName: string;
  totalRamMB: number;
}


const fetchSolPriceInUSDC = async (): Promise<number> => {
  try {
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    const data = await response.json();
    return data.solana.usd;
  } catch (error) {
    console.error("Error fetching Solana price:", error);
    throw new Error("Failed to fetch Solana price from CoinGecko.");
  }
};

const convertUsdcToSolLamports = async (UsdcPerHour: number): Promise<number> => {
  const solPriceInUsdc = await fetchSolPriceInUSDC();
  const solAmount = UsdcPerHour / solPriceInUsdc;
  const SolPerHourInLamports = solAmount * LAMPORTS_PER_SOL;
  return SolPerHourInLamports;
};

export async function startAffair() {
  // Initialize

  // Load the shared keypair first
  if (!sharedState.sharedKeypair) {
    const encryptedKeypair = await ServerManager.loadEncryptedKeypairFromServer();
    const userPassword = prompt("Please enter your password for keypair decryption:");
    if (encryptedKeypair && userPassword !== null) {
      try {
        const decryptedKeypair = await EncryptionManager.decryptED25519Keypair(
          encryptedKeypair,
          userPassword,
          encryptedKeypair.salt
        );
        // Update sharedState
        sharedState.sharedKeypair = Keypair.fromSecretKey(decryptedKeypair.ed25519PrivateKey);
      } catch (error) {
        console.error('Failed to load and decrypt keypair:', error);
        return;  // Stop the execution if the keypair fails to load or decrypt
      }
    }
  }

  // Step 0: Initialize the lender if necessary
  if (sharedState.sharedKeypair != null) {
    const lenderInitialized = await initializeLenderIfNecessary(sharedState.sharedKeypair, connection);

    if (!lenderInitialized) {
      console.error("Failed to initialize lender");
      throw new Error("Failed to initialize lender");
    }

    console.log("Lender has been initialized or already exists");
  }

// Now you have the shared keypair, let's check if an affair already exists
  if (sharedState.sharedKeypair) {
    const accountInfo = await checkIfAffairExists(); // Updated function that returns AccountInfo<Buffer> | null
    if (accountInfo !== null) { // Checking if affair exists
      console.error("Affair already initialized");
      let errorMessageElement = document.getElementById("error-message");
      if (errorMessageElement) {
        errorMessageElement.innerText = 'Affair already initialized.';
      } else {
        console.error("Element with id 'error-message' was not found.");
      }
      return Promise.reject(new Error("Affair already initialized"));
    }
  } else {
    console.error('Shared keypair is null. Cannot proceed.');
    let errorMessageElement = document.getElementById("error-message");
    if (errorMessageElement) {
      errorMessageElement.innerText = 'Shared keypair is null. Cannot proceed.';
    } else {
      console.error("Element with id 'error-message' was not found.");
    }
  }


  await (async () => {
    let userPassword = null;
    let isVerified = false;
    let systemInfo: SystemInfo | null = null;
    let parsedUsdcPerHour = NaN;
    let parsedSolPerHourInLamports = 0;
    let parsedLendingDuration = NaN;
    let isSystemInfoValid = false;
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
    // Fetch System Info Loop
    while (!isSystemInfoValid) {
      try {
        systemInfo = await fetchSystemInfo();

        if (systemInfo !== null && !systemInfo.ipAddress.startsWith('<HEAD>')) {
          console.log("Successfully fetched system info:", systemInfo);
          isSystemInfoValid = true; // Successfully fetched system info, so set the flag to true
        } else {
          console.error('Invalid or incomplete system info. Retrying...');
        }
      } catch (e) {
        console.error('An error occurred while fetching system info. Retrying...');
      }
    }
    // USDC Rate Loop
    while (isNaN(parsedUsdcPerHour)) {
      try {
        const usdcPerHour = prompt("Please enter how many USDC per hour you require:");
        // User cancelled the prompt
        if (usdcPerHour === null) {
          console.error('USDC rate prompt cancelled.');
          return;
        }
        parsedUsdcPerHour = parseFloat(usdcPerHour);
        // Check if the entered value is a number
        if (isNaN(parsedUsdcPerHour)) {
          console.error('Invalid USDC rate entered. Please enter a valid number.');
        } else {
          // If it is, proceed to convert USDC to SOL in Lamports
          try {
            parsedSolPerHourInLamports = await convertUsdcToSolLamports(parsedUsdcPerHour);
            console.log(`Converted ${parsedUsdcPerHour} USDC to ${parsedSolPerHourInLamports} SOL in lamports.`);
          } catch (conversionError) {
            console.error('Failed to convert USDC to SOL:', conversionError);
            // Decide how to proceed; you might want to break the loop, return, or revert to asking for input again
          }
        }
      } catch (e) {
        console.error('An error occurred during USDC rate input:', e);
        // Decide how to proceed; you might want to break the loop or return
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
    console.log(`Successfully parsed lending duration: ${parsedLendingDuration} hours.`);
    // Calculate affairTerminationTime (current Unix timestamp + lending duration in seconds)
    const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
    const affairTerminationTime = currentTime + (parsedLendingDuration * 3600);
    // Prepare payload
    if (systemInfo !== null) {
    const payload = {
      systemInfo,
      solPerHour: parsedSolPerHourInLamports,
      affairTerminationTime
    };
    console.log(`Calculated affair termination time: ${affairTerminationTime}`);
    // Create session account on Solana & save sessionAccountPublicKey in sharedState for future use
      if (sharedState.sharedKeypair) {
        try {
          await createShagaAffair(payload, sharedState.sharedKeypair);
          // Initiate the polling loop
          initiatePollingLoop();
          console.log('Successfully created Shaga affair.');
        } catch (error) {
          console.error('Failed to create Shaga affair:', error);
          return;
        }
      } else {
        console.error('System info is null. Cannot proceed.');
        return;
      }
    }
  })();
}

export async function initiatePollingLoop() {
  while (sharedState.isAffairInitiated) { // until the affair is active
    await ServerManager.pollForPin(); // if there is a rental, it polls Solana, if there is no rental it polls the backend
    await new Promise(resolve => setTimeout(resolve, 500));
  }
}
