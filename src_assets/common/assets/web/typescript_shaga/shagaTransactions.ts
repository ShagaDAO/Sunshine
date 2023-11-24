// shagaTransactions.ts

import { loadAndDecryptKeypair } from "./shagaUIManager";
import {
  Affair,
  AffairPayload,
  AffairState,
  HashAlgorithm
} from "../../../../../third-party/Shaga-Program/app/shaga/src/generated";
import {
  createAffair,
  createLender,
  terminateAffair
} from "../../../../../third-party/Shaga-Program/app/shaga/src/custom";
import { AccountInfo, Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { connection, ServerManager } from "./serverManager";
import {
  signAndSendTransactionInstructionsModified
} from "../../../../../third-party/Shaga-Program/app/shaga/src/utils";
import {
  findAffair,
  findAffairList,
  findLender,
  findRentAccount,
  findRentEscrow,
  findVault
} from "../../../../../third-party/Shaga-Program/app/shaga/src/pda";
import {
  hashValueSha256
} from "../../../../../third-party/Shaga-Program/app/shaga/src/hash";
import { refreshInitiateAffair, refreshTerminateAffair, refreshTerminateRental, sharedState } from "./sharedState";
import BN from "bn.js";
import { SystemInfo } from "./initializeAffair";

// Define the path to the file where lender states are stored TODO: Write backend endpoint & append there
// transactionLogFilePath = './transactionLogs.json';


function validateCoordinates(coordinates: string): boolean {
  // Regular expression to match the coordinates pattern ±DD.DDD,±DDD.DDD
  const regex = /^[+-]?\d{1,2}(\.\d{1,3})?,\s*[+-]?\d{1,3}(\.\d{1,3})?$/;
  if (!regex.test(coordinates)) {
    return false;
  }
  // Split the coordinates into latitude and longitude
  const [lat, long] = coordinates.split(',').map(coord => parseFloat(coord.trim()));
  // Validate latitude and longitude ranges
  if (lat < -90 || lat > 90 || long < -180 || long > 180) {
    return false;
  }

  return true;
}

function validateAffairPayload(payload: AffairPayload): boolean {
  // Validate IP Address
  const ipSegments = payload.ipAddress.split('.');
  const validIp = ipSegments.length === 4 && ipSegments.every(segment => {
    const num = Number(segment);
    return !isNaN(num) && num <= 255;
  });
  // Validate totalRamMb (Minimum 3GB = 3072MB or 4GB = 4096MB)
  const validRam = payload.totalRamMb >= 3072; // Replace 3072 with 4096 for at least 4GB
  // Validate other fields for not-null or appropriate types
  const validCpuName = Boolean(payload.cpuName);
  const validGpuName = Boolean(payload.gpuName);
  const validSolPerHour = Boolean(payload.solPerHour);
  const validAffairTerminationTime = Boolean(payload.affairTerminationTime);
  const validCoordinates = validateCoordinates(payload.coordinates);

  // Validate SHA-256 hash (if session is private)
  let validHash = true;
  if (sharedState.sessionPassword !== null && payload.privatePairHash !== null) {
    const hashHex = Array.prototype.map.call(payload.privatePairHash, x => ('00' + x.toString(16)).slice(-2)).join('');
    validHash = /^[a-f0-9]{64}$/i.test(hashHex);
  }

  // Combine all validations including the new coordinates validation
  const isValid = validIp && validRam && validCpuName && validGpuName && validSolPerHour && validAffairTerminationTime && validCoordinates && validHash;

  // Debug Outputs
  console.log('Is IP valid:', validIp);
  console.log('Is RAM valid:', validRam);
  console.log('Is CPU name valid:', validCpuName);
  console.log('Is GPU name valid:', validGpuName);
  console.log('Is Sol per hour valid:', validSolPerHour);
  console.log('Is Affair termination time valid:', validAffairTerminationTime);
  console.log('Is payload valid:', isValid);
  console.log('Is Coordinates valid:', validCoordinates);
  console.log('Is SHA-256 hash valid:', validHash);
  console.log('Is payload valid:', isValid);

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
  // Check if affairAccountPublicKey is null before making the RPC call
  if (sharedState.affairAccountPublicKey === null) {
    console.log("affairAccountPublicKey is null. Skipping RPC call.");
    sharedState.isAffairInitiated = false;
    return null;
  }
  let accountInfo: AccountInfo<Buffer> | null = null;
  try {
    accountInfo = await connection.getAccountInfo(<PublicKey>new PublicKey(sharedState.affairAccountPublicKey));
  } catch (error) {
    console.error(`Error checking affair initialization: ${error}`);
    return null;
  }
  // Update the shared state
  sharedState.isAffairInitiated = accountInfo !== null;
  return accountInfo;
}


function formatCoordinates(coordinates: string): string {
  const [lat, long] = coordinates.split(',');

  const formattedLat = lat.startsWith('-') ? lat : `+${lat}`;
  const formattedLong = long.startsWith('-') ? long : `+${long}`;

  return `${formattedLat},${formattedLong}`;
}

export async function createShagaAffair(
  payload: { systemInfo: SystemInfo, solPerHour: number, affairTerminationTime: number },
  serverKeypair: Keypair,
): Promise<void> {

  const { systemInfo, solPerHour, affairTerminationTime } = payload;

  // Extract and format the coordinates using the external function
  const coordinates = formatCoordinates(systemInfo.coordinates)
  const ipAddressArray = systemInfo.ipAddress
  const cpuNameArray = systemInfo.cpuName
  const gpuNameArray = systemInfo.gpuName
  const solPerHourBN = new BN(solPerHour);
  const affairTerminationTimeBN = new BN(affairTerminationTime);

  const isPrivateSession = sharedState.sessionPassword !== null; // if password is null, then it's not private

  const affairPayload: AffairPayload = {
    coordinates: coordinates,
    ipAddress: ipAddressArray,
    cpuName: cpuNameArray,
    gpuName: gpuNameArray,
    totalRamMb: Number(systemInfo.totalRamMB),
    solPerHour: solPerHourBN,
    affairTerminationTime: affairTerminationTimeBN,
    hashAlgorithm: isPrivateSession ? HashAlgorithm.Sha256 : HashAlgorithm.None,
    privatePairHash: isPrivateSession ? await hashValueSha256(sharedState.sessionPassword!) : undefined
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
  console.log("hello: ", serverKeypair.publicKey.toBase58());

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

      // const extendedTimeout = 30000;

      // await new Promise<void>((resolve, reject) => {
      //   let confirmed = false;

      //   const timeout = setTimeout(() => {
      //     if (!confirmed) {
      //       reject(new Error('Transaction confirmation timed out'));
      //     }
      //   }, extendedTimeout);

      //   connection.onSignature(signature, (result, context) => {
      //     clearTimeout(timeout);
      //     if (result.err) {
      //       reject(new Error(`Transaction failed: ${result.err}`));
      //     } else {
      //       console.log(`Transaction ${signature} confirmed at block ${context.slot}`);
      //       confirmed = true;
      //       resolve();
      //     }
      //   });
      // });

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

    // Reset the session password in sharedState to null
    sharedState.sessionPassword = null;

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