// shagaTransactions.ts

import { loadAndDecryptKeypair, SystemInfo } from "./shagaUIManager";
import {
  Affair, AffairPayload, AffairState, createInitializeLenderInstruction, createTerminateAffairInstruction,
  createTerminateVacantAffairInstruction
} from "../../../../../third-party/shaga-program/app/shaga_joe/src/generated";
import { createAffair, createLender,terminateAffair } from "../../../../../third-party/shaga-program/app/shaga_joe/src/custom";
import { AccountInfo, Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { API_BASE_URL, connection, ServerManager } from "./serverManager";
import {  signAndSendTransactionInstructionsModified} from "../../../../../third-party/shaga-program/app/shaga_joe/src/utils";
import {  findAffair,  findAffairList,  findLender,  findRentAccount,
  findRentEscrow, findThreadAuthority, findVault} from "../../../../../third-party/shaga-program/app/shaga_joe/src/pda";
import { refreshInitiateAffair, refreshTerminateAffair, refreshTerminateRental, sharedState } from "./sharedState";
import BN from "bn.js";

// Define the path to the file where lender states are stored TODO: Write backend endpoint & append there
// transactionLogFilePath = './transactionLogs.json';

function validateAffairPayload(payload: AffairPayload): boolean {
  // Validate IP Address
  const ipSegments = payload.ipAddress.split('.');
  const validIp = ipSegments.length === 4 && ipSegments.every(segment => {
    const num = Number(segment);
    return !isNaN(num) && num < 255;
  });

  // Validate totalRamMb (Minimum 3GB = 3072MB or 4GB = 4096MB)
  const validRam = payload.totalRamMb >= 3072; // Replace 3072 with 4096 for at least 4GB

  // Validate other fields for not-null or appropriate types
  const validCpuName = Boolean(payload.cpuName);
  const validGpuName = Boolean(payload.gpuName);
  const validSolPerHour = Boolean(payload.solPerHour);
  const validAffairTerminationTime = Boolean(payload.affairTerminationTime);

  // Combine all validations
  const isValid = validIp && validRam && validCpuName && validGpuName && validSolPerHour && validAffairTerminationTime;

  // Debug Outputs
  console.debug('Is IP valid:', validIp);
  console.debug('Is RAM valid:', validRam);
  console.debug('Is CPU name valid:', validCpuName);
  console.debug('Is GPU name valid:', validGpuName);
  console.debug('Is Sol per hour valid:', validSolPerHour);
  console.debug('Is Affair termination time valid:', validAffairTerminationTime);
  console.debug('Is payload valid:', isValid);

  return isValid;
}


// TODO: MOVE MOST OF THE CODE TO THE BACKEND, THIS IS UNSUSTAINABLE AND BAD PRACTICE, IF THE USER IS AFK
// Main function to check the rental state
export async function checkRentalState(): Promise<void> {
  // Step 1: Check if wasRentalActive is false
  if (!sharedState.wasRentalActive) {
    console.log('Rental is not active. No need to check.');
    return;
  }

  const accountInfo = await checkIfAffairExists();

  if (accountInfo === null) {
    console.log('Account does not exist, likely terminated by the system.');
    await refreshTerminateAffair();
    await ServerManager.unpairAllClients();
    return;
  }

  let affair;
  try {
    [affair] = Affair.fromAccountInfo(accountInfo);
  } catch (error) {
    console.error(`Error deserializing affair state: ${error}`);
    return;
  }

  if (affair.affairState === AffairState.Available) {
    console.log('Affair is now AVAILABLE, rental was canceled.');
    await refreshTerminateRental();
    await ServerManager.unpairAllClients();
  } else {
    console.log('Affair is still UNAVAILABLE, no action needed.');
    // Do nothing
  }
}



export async function checkIfAffairExists(): Promise<AccountInfo<Buffer> | null> {
  let accountInfo: AccountInfo<Buffer> | null = null;
  try {
    accountInfo = await connection.getAccountInfo(<PublicKey>sharedState.affairAccountPublicKey);
  } catch (error) {
    console.error(`Error checking affair initialization: ${error}`);
    return null;
  }
  // Update the shared state
  sharedState.isAffairInitiated = accountInfo !== null;

  return accountInfo;
}



export async function createShagaAffair(
  payload: { systemInfo: SystemInfo, solPerHour: number, affairTerminationTime: number },
  serverKeypair: Keypair
): Promise<void> {

  // Step 0: Initialize the lender if necessary
  const lenderInitialized = await initializeLenderIfNecessary(serverKeypair, connection);

  if (!lenderInitialized) {
    console.error("Failed to initialize lender");
    throw new Error("Failed to initialize lender");
  }

  console.log("Lender has been initialized or already exists");

  const { systemInfo, solPerHour, affairTerminationTime } = payload;

  const ipAddressArray = systemInfo.ipAddress
  const cpuNameArray = systemInfo.cpuName
  const gpuNameArray = systemInfo.gpuName
  const solPerHourBN = new BN(solPerHour);
  const affairTerminationTimeBN = new BN(affairTerminationTime);

  const affairPayload: AffairPayload = {
    ipAddress: ipAddressArray,
    cpuName: cpuNameArray,
    gpuName: gpuNameArray,
    totalRamMb: Number(systemInfo.totalRamMB),
    solPerHour: solPerHourBN,
    affairTerminationTime: affairTerminationTimeBN
  };
  // Validate the payload
  console.debug('Constructed Payload:', JSON.stringify(affairPayload));  // Before validation

  console.debug('Constructed Payload:', affairPayload);  // Before validation
  if (!validateAffairPayload(affairPayload)) {
    console.error('Payload failed validation:', affairPayload);  // If validation fails
    throw new Error('Validation failed: Invalid payload data');
  }
  // Initialize the authority with the server's public key
  const authority = serverKeypair.publicKey;
  // Create the 'createAffair' instruction
  const createAffairIx = createAffair(authority, affairPayload);
  // Create a new transaction
  const transaction = new Transaction().add(createAffairIx);
  // Extract the TransactionInstructions from the Transaction
  const instructionArray = transaction.instructions;
  // Log the inputs for debugging purposes
  console.log("Affair Payload:", affairPayload);
  console.log("Authority:", authority.toString());
  console.log("Transaction Instructions:", instructionArray);
  console.log(serverKeypair.publicKey.toBase58())

  try {
    // Sign and send the transaction
    const signature = await signAndSendTransactionInstructionsModified(
      connection,
      [serverKeypair],
      serverKeypair,
      instructionArray,
      true
    );

    // The transaction is already confirmed, so no need to check again
    console.log(`Transaction ${signature} confirmed`);
    //transactionLog('createAffair', signature); removed but would be useful to add
    // Calculate the return
    const [affairAccountPublicKey] = findAffair(serverKeypair.publicKey);
    await refreshInitiateAffair(affairAccountPublicKey);

  } catch (error) {
    console.error(`Transaction failed: ${error}`);
    throw new Error(`Transaction failed with additional context: ${error}`);
  }
}

// Function to initialize lender if necessary
export async function initializeLenderIfNecessary(serverKeypair: Keypair, connection: Connection): Promise<boolean> {
  // Step 1: Check if the lender is already initialized
  const [lenderPDA] = findLender(serverKeypair.publicKey);

  let accountInfo;
  try {
    accountInfo = await connection.getAccountInfo(lenderPDA);
  } catch (error) {
    console.error(`Error checking lender initialization: ${error}`);
    return false;
  }

  // Step 2: If the lender is not initialized, initialize it
  if (accountInfo === null) {
    try {
      const initializeLenderIx = createLender(serverKeypair.publicKey);

      const signature = await signAndSendTransactionInstructionsModified(
        connection,
        [serverKeypair],
        serverKeypair,
        [initializeLenderIx],
        true
      );

      const extendedTimeout = 30000;

      await new Promise<void>((resolve, reject) => {
        let confirmed = false;

        const timeout = setTimeout(() => {
          if (!confirmed) {
            reject(new Error('Transaction confirmation timed out'));
          }
        }, extendedTimeout);

        connection.onSignature(signature, (result, context) => {
          clearTimeout(timeout);
          if (result.err) {
            reject(new Error(`Transaction failed: ${result.err}`));
          } else {
            console.log(`Transaction ${signature} confirmed at block ${context.slot}`);
            confirmed = true;
            resolve();
          }
        });
      });

      return true;

    } catch (error) {
      console.error(`Lender initialization failed: ${error}`);
      return false;
    }
  }

  return true;
}


export async function terminateAffairButton() {
  // Step 0: Initialize serverKeypair
  if (sharedState.sharedKeypair === null) {
    loadAndDecryptKeypair();
  }
  const serverKeypair = sharedState.sharedKeypair;

  if (serverKeypair === null) {
    throw new Error("Server keypair is not initialized");
  }

  try {
    // Step 1: Check if the affair exists and is active
    const [affairAddress] = findAffair(serverKeypair.publicKey);
    const accountInfo = await connection.getAccountInfo(affairAddress);

    if (accountInfo === null) {
      throw new Error("No active affair found");
    }
    // Step 2: Fetch the affair data and check if it's vacant
    const affairData = await Affair.fromAccountAddress(connection, affairAddress);
    let vacant = !affairData.rental;

    // Step 3: Get the appropriate termination instruction
    const terminateAffairIx = await terminateAffair(
      connection,
      serverKeypair.publicKey,
      affairAddress,
      vacant
    );
    // Step 4: Retrieve necessary accounts for the transaction
    const [affairsList] = findAffairList();
    const [vault] = findVault();
    const [escrow] = findRentEscrow(affairData.authority, affairData.client);
    const [rental] = findRentAccount(affairData.authority, affairData.client);
    // Step 5: Execute the transaction
    const signature = await signAndSendTransactionInstructionsModified(
      connection,
      [serverKeypair],
      serverKeypair,
      [terminateAffairIx],
      true // confirm the transaction
    );

    console.log(`Transaction ${signature} confirmed`);
    console.log("Affair terminated successfully");
    // Step 6: Terminate any additional connections or threads
    await refreshTerminateAffair();
    await ServerManager.unpairAllClients() // TODO: Check if needs to also call close app or if it's automated

  } catch (error) {
    console.error(`Error in terminating affair: ${error}`);
    throw new Error(`Error in terminating affair: ${error}`);
  }
}

/*
function transactionLog(instruction: string, signature: string) {
  const currentTime = new Date().toISOString();
  const logData = {
    instruction: instruction,
    signature: signature,
    loggedAt: currentTime
  };

  // Append the new log to the file
  try {
    fs.appendFileSync(transactionLogFilePath, JSON.stringify(logData, null, 2) + '\n', 'utf8');
  } catch (error) {
    console.error(`Error writing transaction logs: ${error}`);
    throw new Error(`Error writing transaction logs: ${error}`);
  }
}
*/