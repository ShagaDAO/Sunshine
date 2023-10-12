// sharedState.ts

import { Keypair, PublicKey } from '@solana/web3.js';
import { checkRentalState } from "./shagaTransactions";
import { ServerManager } from "./serverManager";


// Define the type for the full sharedState
export type SharedStateType = {
  isRentPaid: boolean;
  isEncryptedPinReceived: boolean;
  sharedKeypair: Keypair | null;
  affairAccountPublicKey: PublicKey | null;
  isAffairInitiated: boolean;
  wasRentalActive: boolean;
};

// Define the type for the part of the state that gets saved
export type SafeSharedStateType = {
  isRentPaid: boolean;
  isEncryptedPinReceived: boolean;
  affairAccountPublicKey: PublicKey | null;
  isAffairInitiated: boolean;
  wasRentalActive: boolean;
};


// Your existing sharedState object with a type assertion
export const sharedState: SharedStateType = {
  isRentPaid: false,
  isEncryptedPinReceived: false,
  sharedKeypair: null,
  affairAccountPublicKey: null,
  isAffairInitiated: false,
  wasRentalActive: false,
};

export async function refreshTerminateAffair(): Promise<void> { // TODO: v.2 has all logic directly on the C++ Backend
  try {
    sharedState.isRentPaid = false;
    sharedState.isEncryptedPinReceived = false;
    sharedState.affairAccountPublicKey = null;
    sharedState.isAffairInitiated = false;
    sharedState.wasRentalActive = false;

    await ServerManager.backupSharedStateToBackend();
  } catch (error) {
    console.error("Failed to backup shared state after terminating affair:", error);
    // Handle the error as appropriate for your application
  }
}

// TODO: v.2 has all logic directly on the C++ Backend

export async function refreshInitiateAffair(affairPublicKey: PublicKey): Promise<void> {
  try {
    sharedState.isRentPaid = false;
    sharedState.isEncryptedPinReceived = false;
    sharedState.affairAccountPublicKey = affairPublicKey;
    sharedState.isAffairInitiated = true;
    sharedState.wasRentalActive = false;

    await ServerManager.backupSharedStateToBackend();
  } catch (error) {
    console.error("Failed to backup shared state after initiating affair:", error);
    // Handle the error as appropriate for your application
  }
}


export async function refreshTerminateRental(): Promise<void> {
  try {
    sharedState.isRentPaid = false;
    sharedState.isEncryptedPinReceived = false;
    sharedState.wasRentalActive = false;

    await ServerManager.backupSharedStateToBackend();
  } catch (error) {
    console.error("Failed to backup shared state after terminating rental:", error);
    // Handle the error as appropriate for your application
  }
}
