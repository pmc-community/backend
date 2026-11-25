// scripts/generate-key.ts
import crypto from 'node:crypto';

function generateApiKey(prefix = 'sk_live'): string {
  return `${prefix}_${crypto.randomBytes(24).toString('hex')}`;
}

function hashKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

const rawKey = generateApiKey();
const hash = hashKey(rawKey);

console.log('Raw key (give this to the consumer, shown only once):');
console.log(rawKey);
console.log('\nHash to store in your key store:');
console.log(hash);