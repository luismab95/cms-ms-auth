import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import {
  ForgotPasswordDto,
  LoginAuthDto,
  ResetPasswordDto,
  TwoFactorAuthDto,
  UserI,
} from './dto/auth.dto';
import { AuthRepository } from './repositories/auth.repository';
import { maskString } from 'src/shared/helpers/string.helper';
import {
  comparePasswords,
  hashPassword,
} from 'src/shared/helpers/bcrypt.helper';
import { randomCharacters } from 'src/shared/helpers/random.helper';
import {
  TokenInterface,
  generateForgotPassword,
  generateRefreshToken,
  generateToken,
  verifyToken,
} from 'src/shared/helpers/jwt.helper';
import { OK_200 } from 'src/shared/constants/message.constants';
import { EmailInterface, sendMail } from 'src/shared/helpers/email.helper';
import { config } from 'src/shared/environments/load-env';
import { getParameter } from 'src/shared/helpers/parameter.helper';

@Injectable()
export class AuthService {
  constructor(private readonly authRepository: AuthRepository) {}

  async login(loginAuthDto: LoginAuthDto) {
    const userLogin = await this.authRepository.findUser(loginAuthDto);

    if (userLogin === undefined || userLogin.bloqued || !userLogin.status)
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );

    const isMatch = await comparePasswords(
      loginAuthDto.password,
      userLogin.password,
    );

    if (!isMatch) {
      const bloqueUser = await this.createAttemptLogin(userLogin);
      if (bloqueUser) {
        await this.authRepository.updatedStatusAttempt(userLogin.id, false);
        throw new HttpException(
          'Su cuenta ha sido bloqueada por razones de seguridad, debido a múltiples intentos de acceso fallidos.',
          HttpStatus.BAD_REQUEST,
        );
      }
      throw new HttpException(
        'Las creedenciales son incorrectas.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (userLogin.twoFactorAuth) {
      await this.generateOpt(userLogin, 'LOGIN');
      return `Se ha enviado un código de verificación para inicio de sesión a la dirección de correo ${maskString(userLogin.email)}.`;
    }

    await this.authRepository.updatedStatusAttempt(userLogin.id, false);
    return await this.createSession(
      userLogin,
      loginAuthDto.ipAddress,
      loginAuthDto.info,
    );
  }

  async twoFactorAuth(twoFactorAuthDto: TwoFactorAuthDto) {
    const userLogin = await this.authRepository.findUser({
      email: twoFactorAuthDto.email,
      password: '',
    });

    if (userLogin === undefined || userLogin.bloqued || !userLogin.status) {
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const findOtpUser = await this.authRepository.findOtpUser(
      userLogin.id,
      'LOGIN',
    );

    if (findOtpUser === undefined) {
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const isMatch = twoFactorAuthDto.otp === findOtpUser.otp;
    if (!isMatch) {
      const bloqueUser = await this.createAttemptLogin(userLogin);
      if (bloqueUser) {
        await this.authRepository.updatedStatusAttempt(userLogin.id, false);
        throw new HttpException(
          'Su cuenta ha sido bloqueada por razones de seguridad, debido a múltiples intentos de acceso fallidos.',
          HttpStatus.BAD_REQUEST,
        );
      }
      throw new HttpException(
        'El código de verificación OTP es incorrecto.',
        HttpStatus.BAD_REQUEST,
      );
    }
    await this.authRepository.updatedOtpUser(
      twoFactorAuthDto.otp,
      userLogin.id,
      'LOGIN',
    );

    await this.authRepository.updatedStatusAttempt(userLogin.id, false);
    return await this.createSession(
      userLogin,
      twoFactorAuthDto.ipAddress,
      twoFactorAuthDto.info,
    );
  }

  async generateOpt(userLogin: UserI, type: 'LOGIN' | 'RESET-PASSWORD') {
    const otpType = (await getParameter('OTP_TYPE')) as
      | 'NUMBER'
      | 'LETTER'
      | 'COMBINED';
    const otpLength = await getParameter('OTP_LONG');
    const otp = randomCharacters(otpType, Number(otpLength));
    await this.authRepository.generateOpt(userLogin.id, type, otp);
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const URlStatics = await getParameter('APP_STATICS_URL');
    const logoMail = await getParameter('LOGO_MAIL');
    const emailData = {
      templateName: 'login',
      subject: 'Código OTP para Inicio de Sesión',
      to: userLogin.email,
      context: {
        fullName: `${userLogin.firstname} ${userLogin.lastname}`,
        companyName: await getParameter('COMPANY_NAME'),
        mailFooter: await getParameter('COMPANY_MAIL'),
        imageHeader: `${URlStatics}/${logoMail}`,
        year: currentYear,
        code: otp,
      },
    } as EmailInterface;
    sendMail(emailData);
  }

  async createSession(userLogin: UserI, ipAddress: string, info: string) {
    const { id, email, firstname, lastname, roleId } = userLogin;
    const token = generateRefreshToken({
      userId: id,
      roleId,
      email,
      firstname,
      lastname,
    });
    const session = await this.authRepository.createSession(
      userLogin.id,
      ipAddress,
      info,
      token,
    );
    return generateToken({
      userId: id,
      roleId,
      email,
      firstname,
      lastname,
      sessionId: session.id,
    });
  }

  async createAttemptLogin(userLogin: UserI) {
    const findAttempt = await this.authRepository.getLastAttempt(userLogin.id);
    const attempt = findAttempt === undefined ? 1 : findAttempt.attempt + 1;

    const attemptParameter = await getParameter('APP_ATTEMPS_LOGIN');

    await this.authRepository.createAttempt(userLogin.id, attempt);
    if (attempt >= Number(attemptParameter)) {
      await this.authRepository.toggleBloquedUser(userLogin.id, true);
      return true;
    }
    return false;
  }

  async signOut(token: string) {
    const tokenPayload = verifyToken(token) as TokenInterface;
    await this.authRepository.updatedSession(tokenPayload.sessionId, false);
    return OK_200;
  }

  async forgorPassword(forgotPasswordDto: ForgotPasswordDto) {
    const userLogin = await this.authRepository.findUser({
      email: forgotPasswordDto.email,
      password: '',
    });

    if (userLogin === undefined || userLogin.bloqued || !userLogin.status)
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );

    const forgotPasswordToken = generateForgotPassword({
      email: userLogin.email,
      roleId: userLogin.roleId,
      firstname: userLogin.firstname,
      lastname: userLogin.lastname,
      userId: userLogin.id,
    });

    const { frontendUrl } = config.server;
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const URlStatics = await getParameter('APP_STATICS_URL');
    const logoMail = await getParameter('LOGO_MAIL');
    const emailData = {
      templateName: 'forgot-password',
      subject: 'Restablecer contraseña',
      to: userLogin.email,
      context: {
        fullName: `${userLogin.firstname} ${userLogin.lastname}`,
        companyName: await getParameter('COMPANY_NAME'),
        mailFooter: await getParameter('COMPANY_MAIL'),
        imageHeader: `${URlStatics}/${logoMail}`,
        year: currentYear,
        link: `${frontendUrl}/auth/reset-password?token=${forgotPasswordToken}`,
      },
    } as EmailInterface;
    sendMail(emailData);
    return `Se ha enviado un enlace para resetear la contraseña a la dirección de correo ${maskString(userLogin.email)}.`;
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const tokenPayload = verifyToken(resetPasswordDto.token) as TokenInterface;

    const userLogin = await this.authRepository.findUser({
      email: tokenPayload.email,
      password: '',
    });

    if (userLogin === undefined || userLogin.bloqued || !userLogin.status)
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );

    userLogin.password = await hashPassword(resetPasswordDto.password);
    await this.authRepository.updatedUser(userLogin.id, userLogin);

    return 'Tu contraseña ha sido restablecida.';
  }
}
