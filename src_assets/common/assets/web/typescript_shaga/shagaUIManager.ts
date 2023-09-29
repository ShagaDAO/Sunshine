import { createWallet } from './createWallet';
import { fetchSystemInfo } from "./serverManager";


export const messageDisplay = document.getElementById('messageDisplay') as HTMLElement;
export interface SystemInfo {
  ipAddress: string;
  cpuName: string;
  gpuName: string;
  totalRamMB: number;
}

export function initializeShagaUI() {
  const fetchInfoBtn = document.getElementById('fetchInfoBtn') as HTMLButtonElement;
  const createWalletBtn = document.getElementById('createWalletBtn') as HTMLButtonElement;
  const systemInfoDisplay = document.getElementById('systemInfoDisplay') as HTMLElement;

  console.log('fetchInfoBtn:', fetchInfoBtn);
  console.log('createWalletBtn:', createWalletBtn);
  console.log('systemInfoDisplay:', systemInfoDisplay);
  console.log('messageDisplay:', messageDisplay);

  if (!fetchInfoBtn || !createWalletBtn || !systemInfoDisplay || !messageDisplay) {
    console.error('Essential HTML elements not found.');
    return;
  }


  // Attaching event listeners
  fetchInfoBtn.addEventListener('click', async () => {
    try {
      const systemInfo = await fetchSystemInfo();
      if (systemInfo) {
        systemInfoDisplay.innerHTML = `
          IP Address: ${systemInfo.ipAddress}<br>
          CPU Name: ${systemInfo.cpuName}<br>
          GPU Name: ${systemInfo.gpuName}<br>
          Total RAM: ${systemInfo.totalRamMB} MB
        `;
      } else {
        systemInfoDisplay.innerHTML = 'Failed to fetch system information.';
      }
    } catch (error) {
      console.error('Failed to fetch system info:', error);
      systemInfoDisplay.innerHTML = 'An error occurred while fetching system information.';
    }
  });

  createWalletBtn.addEventListener('click', async () => {
    messageDisplay.className = 'alert alert-info';
    messageDisplay.innerHTML = 'Creating wallet...';
    try {
      await createWallet();
    } catch (error) {
      console.error('Failed to create wallet:', error);
    }
  });

}

// Function to initialize everything
export function initializeApp(): void {
  initializeShagaUI(); // Set up the initial UI
  //TODO: add balance & earnings graphs fetching data from solana
}

// Starting point
document.addEventListener('DOMContentLoaded', async () => {
  initializeApp();  // Initialize your app
});