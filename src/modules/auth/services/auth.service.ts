import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import moment from 'moment';
import {
  comparePasswords,
  maskString,
  getParameter,
  randomCharacters,
  sendMail,
  generateRefreshToken,
  generateToken,
  verifyToken,
  TokenInterface,
  OK_200,
  generateForgotPassword,
  hashPassword,
  EmailI,
  ParameterI,
  config,
} from 'cms-lib-resources';
import { ParameterRepository } from '@shared/repositories/parameter.repository.js';
import { AuthRepository } from '../repositories/auth.repository.js';
import {
  ForgotPasswordDto,
  LoginAuthDto,
  ResendOtpDto,
  ResetPasswordDto,
  TwoFactorAuthDto,
  UserI,
} from '../dto/auth.dto.js';

@Injectable()
export class AuthService {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly parameterRepository: ParameterRepository,
  ) {}

  async login(loginAuthDto: LoginAuthDto) {
    const userLogin = await this.authRepository.findUser(loginAuthDto);

    if (userLogin === undefined || userLogin.bloqued || !userLogin.status)
      throw new HttpException(
        'La cuenta se encuentra inaccesible; puede estar bloqueada o no existe.',
        HttpStatus.BAD_REQUEST,
      );
    const parameters = await this.parameterRepository.getParameters();

    const isMatch = await comparePasswords(
      loginAuthDto.password,
      userLogin.password,
    );

    if (!isMatch) {
      const bloqueUser = await this.createAttemptLogin(userLogin, parameters);
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
      await this.generateOpt(userLogin, 'LOGIN', parameters);
      return `Se ha enviado un código de verificación para inicio de sesión a la dirección de correo ${maskString(userLogin.email)}.`;
    }

    await this.authRepository.updatedStatusAttempt(userLogin.id, false);
    return await this.createSession(
      userLogin,
      loginAuthDto.ipAddress!,
      loginAuthDto.info!,
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
    const parameters = await this.parameterRepository.getParameters();

    const isMatch = twoFactorAuthDto.otp === findOtpUser.otp;
    if (!isMatch) {
      const bloqueUser = await this.createAttemptLogin(userLogin, parameters);
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
      twoFactorAuthDto.ipAddress!,
      twoFactorAuthDto.info!,
    );
  }

  async resendOtp(resendOtpDto: ResendOtpDto) {
    const userLogin = await this.authRepository.findUser({
      email: resendOtpDto.email,
      password: '',
    });

    if (!userLogin)
      throw new HttpException(
        'No se encontro información del inicio de sessión.',
        HttpStatus.BAD_REQUEST,
      );

    const parameters = await this.parameterRepository.getParameters();
    await this.generateOpt(userLogin, 'LOGIN', parameters);
    return `Se ha enviado un código de verificación para inicio de sesión a la dirección de correo ${maskString(userLogin.email)}.`;
  }

  async generateOpt(
    userLogin: UserI,
    type: 'LOGIN' | 'RESET-PASSWORD',
    parameters: ParameterI[],
  ) {
    const otpTimeResend = await getParameter(
      parameters.find((p) => p.code === 'OTP_TIME_RESEND'),
      'OTP_TIME_RESEND',
    );
    const lastOpt = await this.authRepository.findOtpUser(userLogin.id, type);
    if (lastOpt) {
      const validateDate = moment(lastOpt.createdAt).add(
        otpTimeResend,
        'seconds',
      );

      if (!moment().isAfter(validateDate)) {
        throw new HttpException(
          'No puedes generar otro codigo de verificación en estos momentos, espera unos minutos y vuelve a intentarlo.',
          HttpStatus.BAD_REQUEST,
        );
      }
    }

    const otpType = (await getParameter(
      parameters.find((p) => p.code === 'OTP_TYPE'),
      'OTP_TYPE',
    )) as 'NUMBER' | 'LETTER' | 'COMBINED';
    const otpLength = await getParameter(
      parameters.find((p) => p.code === 'OTP_LONG'),
      'OTP_LONG',
    );
    const otp = randomCharacters(otpType, Number(otpLength));
    await this.authRepository.generateOpt(userLogin.id, type, otp);
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const URlStatics = await getParameter(
      parameters.find((p) => p.code === 'APP_STATICS_URL'),
      'APP_STATICS_URL',
    );
    const logoMail = await getParameter(
      parameters.find((p) => p.code === 'LOGO_MAIL'),
      'LOGO_MAIL',
    );
    const emailData = {
      templateName: 'login',
      subject: 'Código OTP para Inicio de Sesión',
      to: userLogin.email,
      context: {
        fullName: `${userLogin.firstname} ${userLogin.lastname}`,
        companyName: await getParameter(
          parameters.find((p) => p.code === 'COMPANY_NAME'),
          'COMPANY_NAME',
        ),
        mailFooter: await getParameter(
          parameters.find((p) => p.code === 'COMPANY_MAIL'),
          'COMPANY_MAIL',
        ),
        imageHeader: `${URlStatics}/${logoMail}`,
        year: currentYear,
        code: otp,
      },
    } as EmailI;
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

  async createAttemptLogin(userLogin: UserI, parameters: ParameterI[]) {
    const findAttempt = await this.authRepository.getLastAttempt(userLogin.id);
    const attempt = findAttempt === undefined ? 1 : findAttempt.attempt + 1;

    const attemptParameter = await getParameter(
      parameters.find((p) => p.code === 'APP_ATTEMPS_LOGIN'),
      'APP_ATTEMPS_LOGIN',
    );

    await this.authRepository.createAttempt(userLogin.id, attempt);
    if (attempt >= Number(attemptParameter)) {
      await this.authRepository.toggleBloquedUser(userLogin.id, true);
      return true;
    }
    return false;
  }

  async signOut(token: string) {
    const tokenPayload = verifyToken(token) as TokenInterface;
    await this.authRepository.updatedSession(tokenPayload.sessionId!, false);
    return OK_200;
  }

  async forgorPassword(forgotPasswordDto: ForgotPasswordDto) {
    const parameters = await this.parameterRepository.getParameters();
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
    const URlStatics = await getParameter(
      parameters.find((p) => p.code === 'APP_STATICS_URL'),
      'APP_STATICS_URL',
    );
    const logoMail = await getParameter(
      parameters.find((p) => p.code === 'LOGO_MAIL'),
      'LOGO_MAIL',
    );
    const emailData = {
      templateName: 'forgot-password',
      subject: 'Restablecer contraseña',
      to: userLogin.email,
      context: {
        fullName: `${userLogin.firstname} ${userLogin.lastname}`,
        companyName: await getParameter(
          parameters.find((p) => p.code === 'COMPANY_NAME'),
          'COMPANY_NAME',
        ),
        mailFooter: await getParameter(
          parameters.find((p) => p.code === 'COMPANY_MAIL'),
          'COMPANY_MAIL',
        ),
        imageHeader: `${URlStatics}/${logoMail}`,
        year: currentYear,
        link: `${frontendUrl}/auth/reset-password?token=${forgotPasswordToken}`,
      },
    } as EmailI;
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
