import * as bcrypt from 'bcryptjs';
import { AES, enc } from 'crypto-js';
import { config } from '../environments/load-env';

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

export async function comparePasswords(
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> {
  const isPasswordCorrect = await bcrypt.compare(plainPassword, hashedPassword);
  return isPasswordCorrect;
}

export function encryptedData(data: string): string {
  const cryptoKey = config.server.cryptoKey;
  const encrypt = AES.encrypt(data, cryptoKey!);
  data = encrypt.toString();
  return data;
}

export function decryptedData(data: any): string {
  const cryptoKey = config.server.cryptoKey;
  data = AES.decrypt(data, cryptoKey!);
  data = data.toString(enc.Utf8);
  return data;
}
