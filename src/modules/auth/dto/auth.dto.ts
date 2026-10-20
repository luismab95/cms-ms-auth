import { Type } from 'class-transformer';
import {
  IsArray,
  IsEmail,
  IsNotEmpty,
  IsNumber,
  ValidateNested,
} from 'class-validator';

export class LoginAuthDto {
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Correo electrónico es requerido.' })
  email: string;

  @IsNotEmpty({ message: 'Contraseña es requerido.' })
  password: string;

  ipAddress?: string;
  info?: string;
}

export class TwoFactorAuthDto {
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Correo electrónico es requerido.' })
  email: string;

  @IsNotEmpty({ message: 'Código de verificación OTP es requerido.' })
  otp: string;

  ipAddress?: string;
  info?: string;
}

export class ResendOtpDto {
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Correo electrónico es requerido.' })
  email: string;
}

export class ForgotPasswordDto {
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Correo electrónico es requerido.' })
  email: string;
}

export class ResetPasswordDto {
  @IsNotEmpty({ message: 'Token es requerido.' })
  token: string;

  @IsNotEmpty({ message: 'Contraseña es requerido.' })
  password: string;
}

export class UserEmailDto {
  @IsNotEmpty({ message: 'Contraseña es requerido.' })
  password: string;
  @IsEmail({}, { message: 'Correo electrónico no válido.' })
  @IsNotEmpty({ message: 'Correo electrónico es requerido.' })
  email: string;
  @IsNumber({}, { message: 'Id no válido.' })
  @IsNotEmpty({ message: 'Id es requerido.' })
  id: number;
}

export class UserDefaultPwdDto {
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => UserEmailDto)
  users: UserEmailDto[];
}

export interface InitializerI {
  id: number;
  hash: string;
  status: boolean;
  userPwd: boolean;
  users?: InitialUserI[];
}

export interface InitialUserI {
  id: number;
  email: string;
  roleId: number;
  roleCode: string;
  roleName: string;
  roleDescription: string;
}

export interface UserI {
  id: number;
  email: string;
  firstname: string;
  lastname: string;
  password: string;
  twoFactorAuth: boolean;
  roleId: number;
  status: boolean;
  bloqued: boolean;
  terms: boolean;
}

export interface SessionI {
  id: number;
  ipAddress: string;
  token: string;
  info: string;
  active: boolean;
  userId: number;
}

export interface LoginAttemptI {
  id: number;
  attempt: number;
  userId: number;
  status: boolean;
}

export interface OtpUserI {
  otp: string;
  createdAt: string;
}
