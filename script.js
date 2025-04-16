const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

// Config
const secret = process.env.JWT_SECRET || 'myjwtsecret';
const encryptionKey = crypto.createHash('sha256').update(String(process.env.ENCRYPT_KEY || 'myencryptionkey')).digest('base64').substr(0, 32);
const iv = crypto.randomBytes(16);

// Step 1: Create the JWT token
const payload = { username: 'student123', role: 'user' };
const token = jwt.sign(payload, secret, { expiresIn: '1h' });

console.log('Original JWT:', token);

// Step 2: Encrypt the token
const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
let encrypted = cipher.update(token);
encrypted = Buffer.concat([encrypted, cipher.final()]);
const encryptedToken = iv.toString('hex') + ':' + encrypted.toString('hex');
console.log('Encrypted JWT:', encryptedToken);

// Step 3: Decrypt the token
const parts = encryptedToken.split(':');
const ivFromToken = Buffer.from(parts[0], 'hex');
const encryptedText = Buffer.from(parts[1], 'hex');

const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryptionKey), ivFromToken);
let decrypted = decipher.update(encryptedText);
decrypted = Buffer.concat([decrypted, decipher.final()]);
const decryptedToken = decrypted.toString();

// Step 4: Verify and decode
try {
  const decoded = jwt.verify(decryptedToken, secret);
  console.log('✅ Success! Decoded JWT:', decoded);
} catch (err) {
  console.error('❌ Decryption or verification failed:', err.message);
}
