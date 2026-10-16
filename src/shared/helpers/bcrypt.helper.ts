import bcrypt from 'bcryptjs';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';
import { config } from '../environments/load-env.js';

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

function getCryptoKey(): string {
  const cryptoKey = config.server.cryptoKey;

  if (!cryptoKey) {
    throw new Error('La clave de cifrado no está configurada');
  }

  return cryptoKey;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

export async function comparePasswords(
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> {
  return bcrypt.compare(plainPassword, hashedPassword);
}

export function encryptedData(data: string): string {
  const cryptoKey = getCryptoKey();
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = scryptSync(cryptoKey, salt, KEY_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    salt.toString('hex'),
    iv.toString('hex'),
    authTag.toString('hex'),
    encrypted.toString('hex'),
  ].join(':');
}

export function decryptedData(data: string): string {
  const parts = data.split(':');

  if (parts.length !== 4 || parts.some((part) => !part)) {
    throw new Error('Formato de datos cifrados inválido');
  }

  const [saltHex, ivHex, authTagHex, encryptedHex] = parts;

  const salt = Buffer.from(saltHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');

  if (
    salt.length !== SALT_LENGTH ||
    iv.length !== IV_LENGTH ||
    authTag.length !== 16 ||
    encrypted.length === 0
  ) {
    throw new Error('Datos cifrados inválidos');
  }

  const key = scryptSync(getCryptoKey(), salt, KEY_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}
