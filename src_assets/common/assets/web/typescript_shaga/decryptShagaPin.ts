import express from 'express';
import bodyParser from 'body-parser';
import { EncryptionManager } from './encryptionManager';
import bs58 from 'bs58';
import { sharedState } from './sharedState';

const app = express();
app.use(bodyParser.json());

app.post('/endpoint', async (req, res) => {
  sharedState.isEncryptedPinReceived = true;

  if (!sharedState.isRentPaid) {
    res.status(402).json({ error: 'Payment required' });
    return;
  }

  if (sharedState.sharedPrivateKey === null) {
    res.status(500).json({ error: 'Server private key not loaded' });
    return;
  }

  const { encryptedPIN, publicKey } = req.body;
  const clientPublicKey = new Uint8Array(bs58.decode(publicKey));

  // Map the decrypted ed25519 private key to its x25519 equivalent
  const mappedKeys = await EncryptionManager.mapEd25519ToX25519(sharedState.sharedPrivateKey, clientPublicKey);

  const decryptedPIN = await EncryptionManager.decryptPinWithX25519PublicKey(
    new Uint8Array(Buffer.from(encryptedPIN, 'hex')),
    mappedKeys.secretKey,
    mappedKeys.publicKey
  );

  res.json({ decryptedPin: decryptedPIN });
});

app.listen(3000, () => {
  console.log('Decryption server running on http://localhost:3000/');
});
