import express from 'express';
import bodyParser from 'body-parser';
import { EncryptionManager } from './encryptionManager';
import bs58 from 'bs58';
import { sharedState } from './sharedState';

const app = express();
app.use(bodyParser.json());

// Function to wait for rent to be paid
const waitForRentPayment = (timeout: number): Promise<void> => {
  return new Promise((resolve, reject) => {
    const checkInterval = 500; // milliseconds
    let elapsedTime = 0;

    const interval = setInterval(() => {
      if (sharedState.isRentPaid) {
        clearInterval(interval);
        resolve();
      }

      elapsedTime += checkInterval;

      if (elapsedTime >= timeout) {
        clearInterval(interval);
        reject(new Error('Rent payment timed out'));
      }
    }, checkInterval);
  });
};

app.post('/endpoint', async (req, res) => {

  if (sharedState.sharedPrivateKey === null) {
    return res.status(500).json({ error: 'Server private key not loaded' });
  }

  const { encryptedPIN, publicKey } = req.body;

  sharedState.isEncryptedPinReceived = true;

  let decodedEncryptedPin;
  try {
    decodedEncryptedPin = new Uint8Array(Buffer.from(encryptedPIN, 'hex'));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid hex-encoded PIN' });
  }

  let clientPublicKey;
  try {
    clientPublicKey = new Uint8Array(bs58.decode(publicKey));
  } catch (e) {
    return res.status(400).json({ error: 'Invalid Base58-encoded public key' });
  }

  const mappedKeys = await EncryptionManager.mapEd25519ToX25519(sharedState.sharedPrivateKey, clientPublicKey);
  const decryptedPIN = await EncryptionManager.decryptPinWithX25519PublicKey(decodedEncryptedPin, mappedKeys.secretKey, mappedKeys.publicKey);

  if (!sharedState.isRentPaid) {
    try {
      // If not paid, enter a waiting state.
      await waitForRentPayment(7000); // Wait for up to 7000 milliseconds
    } catch (error) {
      // If still not paid after waiting, return a 402 status.
      return res.status(402).json({ error: 'Rent payment timed out. Cannot proceed.' });
    }
  }

  // If rent is paid, either initially or after waiting, proceed to send the decrypted PIN.
  return res.json({ decryptedPin: decryptedPIN });
});

app.listen(3000, () => {
  console.log('Decryption server running on http://localhost:3000/');
});
