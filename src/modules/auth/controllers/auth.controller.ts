import {
  Controller,
  Headers,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  HttpStatus,
  Param,
  Patch,
  Delete,
} from '@nestjs/common';
import {
  LoginAuthDto,
  TwoFactorAuthDto,
  ResendOtpDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from '../dto/auth.dto.js';
import { AuthService } from '../services/auth.service.js';
import { ServiceResponseI } from '@shared/interfaces/response.interface.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UsePipes(new ValidationPipe())
  async login(
    @Body() loginAuthDto: LoginAuthDto,
    @Headers() headers: any,
  ): Promise<ServiceResponseI<string>> {
    loginAuthDto.ipAddress = headers['x-client-ip'];
    loginAuthDto.info = headers['x-device-info'];

    return {
      message: await this.authService.login(loginAuthDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Post('two-factor')
  @UsePipes(new ValidationPipe())
  async twoFactorAuth(
    @Body() twoFactorAuthDto: TwoFactorAuthDto,
    @Headers() headers: any,
  ): Promise<ServiceResponseI<string>> {
    twoFactorAuthDto.ipAddress = headers['x-client-ip'];
    twoFactorAuthDto.info = headers['x-device-info'];
    return {
      message: await this.authService.twoFactorAuth(twoFactorAuthDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Post('resend-otp')
  @UsePipes(new ValidationPipe())
  async resendOtp(
    @Body() resendOtpDto: ResendOtpDto,
  ): Promise<ServiceResponseI<string>> {
    return {
      message: await this.authService.resendOtp(resendOtpDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Post('forgot-password')
  @UsePipes(new ValidationPipe())
  async forgorPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ServiceResponseI<string>> {
    return {
      message: await this.authService.forgorPassword(forgotPasswordDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Patch('reset-password')
  @UsePipes(new ValidationPipe())
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<ServiceResponseI<string>> {
    return {
      message: await this.authService.resetPassword(resetPasswordDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Delete('sign-out/:token')
  async singOut(
    @Param('token') token: string,
  ): Promise<ServiceResponseI<string>> {
    return {
      message: await this.authService.signOut(token),
      statusCode: HttpStatus.OK,
    };
  }
}
