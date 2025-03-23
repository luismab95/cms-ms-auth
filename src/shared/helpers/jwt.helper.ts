import * as jwt from 'jsonwebtoken';
import { config } from '../environments/load-env';
import { HttpException, HttpStatus } from '@nestjs/common';
import { ERR_401 } from '../constants/message.constants';

export interface TokenInterface {
  userId: number;
  roleId: number;
  sessionId?: number;
  email: string;
  firstname: string;
  lastname: string;
  iat?: number;
  exp?: number;
}

const { jwtSecretKey, expiresIn } = config.server;

export function generateToken(payload: TokenInterface): string {
  return jwt.sign(payload, jwtSecretKey!, { expiresIn });
}

export function generateRefreshToken(payload: TokenInterface): string {
  return jwt.sign(payload, jwtSecretKey!, { expiresIn: '30d' });
}

export function generateForgotPassword(payload: TokenInterface): string {
  return jwt.sign(payload, jwtSecretKey!, { expiresIn: '10m' });
}

export function generateTemporaltToken(): string {
  return jwt.sign({}, jwtSecretKey!, { expiresIn: '10m' });
}

export function verifyToken(token: string) {
  try {
    return jwt.verify(token, jwtSecretKey);
  } catch (err) {
    throw new HttpException(ERR_401, HttpStatus.UNAUTHORIZED);
  }
}
