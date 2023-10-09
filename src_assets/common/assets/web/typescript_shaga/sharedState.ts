// sharedState.ts

import { Keypair, PublicKey } from '@solana/web3.js';

export const sharedState = {
  isRentPaid: false,
  isEncryptedPinReceived: false,
  sharedKeypair: null as Keypair | null,
  affairAccountPublicKey: null as PublicKey | null,
  isAffairInitiated: false,
};

export function initializeSSE(): void {
  console.log("Initializing SSE...");
  const eventSourceInstance = EventSourceSingleton.getInstance();
  if (eventSourceInstance.eventSource && eventSourceInstance.eventSource.readyState === 1) {
    console.log("EventSource already open. Not reinitializing.");
    return;
  }
  eventSourceInstance.initializeEventSource("https://localhost:47990/sse");
  console.log("SSE initialized.");
}


export function terminateSSE(): void {
  const eventSourceInstance = EventSourceSingleton.getInstance();
  if (eventSourceInstance.eventSource && (eventSourceInstance.eventSource.readyState === 0 || eventSourceInstance.eventSource.readyState === 1)) {
    eventSourceInstance.closeEventSource();
  }
  console.log(`EventSource state after closure: ${eventSourceInstance.eventSource?.readyState}`);
}

// Singleton class to manage the EventSource (SSE)
class EventSourceSingleton {
  private static instance: EventSourceSingleton | null = null;
  public eventSource: EventSource | null = null;
  public retryCount: number = 0;
  public maxRetry: number = 5;  // Maximum number of reconnection attempts

  private constructor() {
    // Singleton pattern: private constructor
  }

  public static getInstance(): EventSourceSingleton {
    if (!EventSourceSingleton.instance) {
      EventSourceSingleton.instance = new EventSourceSingleton();
    }
    return EventSourceSingleton.instance;
  }

  public initializeEventSource(url: string): void {
    if (this.eventSource && (this.eventSource.readyState === 0 || this.eventSource.readyState === 1)) {
      console.log("EventSource is already open or connecting. Not reinitializing.");
      return;
    }

    this.eventSource = new EventSource(url);
    this.retryCount = 0;  // Reset the retry count upon successful initialization

    this.eventSource.onopen = (event: Event) => {
      console.log("EventSource opened", event);
    };

    this.eventSource.onmessage = (event: MessageEvent) => {
      console.log("Received message", event.data);
      if (event.data === 'ping') {
        console.log('Received ping, connection is alive.');
      }
    };

    this.eventSource.onerror = (error: Event) => {
      console.error(`EventSource failed: `, error);
      console.log('EventSource readyState:', this.eventSource?.readyState);  // Additional logging
      this.closeEventSource();
      this.retryConnection(url);  // Attempt to reconnect
    };
  }

  public closeEventSource(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  public retryConnection(url: string): void {
    if (this.retryCount < this.maxRetry) {
      const delay = Math.pow(2, this.retryCount) * 1000;  // Exponential backoff, in milliseconds
      this.retryCount++;
      console.log(`Attempting to reconnect in ${delay / 1000} seconds...`);

      setTimeout(() => {
        this.initializeEventSource("https://localhost:47990/sse");
      }, delay);
    } else {
      console.error("Max retry attempts reached. Not reconnecting.");
    }
  }
}

export default EventSourceSingleton;