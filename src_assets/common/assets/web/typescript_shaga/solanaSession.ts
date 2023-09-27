import { serialize, validate, field } from '@dao-xyz/borsh';
import { SystemInfo } from "./shagaUIManager";

class SessionPayloadSchema {
  public ipAddress: string = '';
  public cpuName: string = '';
  public gpuName: string = '';
  public totalRamMB: number = 0;
  public usdcPerHour: number = 0;

  constructor(data: SessionPayloadSchema) {
    Object.assign(this, data);
  }
}

// Validate the class
validate([SessionPayloadSchema]);

export async function createSolanaSessionAccount(payload: { systemInfo: SystemInfo, usdcPerHour: number }): Promise<string> {
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
  const serializedPayload = serialize(sessionPayload);

  // TODO: Make the RPC call to Solana program to create the session account
  // and return the session public key.

  return 'somePublicKey';  // Placeholder, you'll replace this with the actual public key
}
