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
import { AuthService } from './auth.service';
import {
  ForgotPasswordDto,
  LoginAuthDto,
  ResetPasswordDto,
  TwoFactorAuthDto,
} from './dto/auth.dto';
import { ServiceResponseInterface } from 'src/shared/interfaces/response.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UsePipes(new ValidationPipe())
  async login(
    @Body() loginAuthDto: LoginAuthDto,
    @Headers() headers: any,
  ): Promise<ServiceResponseInterface<string>> {
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
  ): Promise<ServiceResponseInterface<string>> {
    twoFactorAuthDto.ipAddress = headers['x-client-ip'];
    twoFactorAuthDto.info = headers['x-device-info'];
    return {
      message: await this.authService.twoFactorAuth(twoFactorAuthDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Post('forgot-password')
  @UsePipes(new ValidationPipe())
  async forgorPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
  ): Promise<ServiceResponseInterface<string>> {
    return {
      message: await this.authService.forgorPassword(forgotPasswordDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Patch('reset-password')
  @UsePipes(new ValidationPipe())
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
  ): Promise<ServiceResponseInterface<string>> {
    return {
      message: await this.authService.resetPassword(resetPasswordDto),
      statusCode: HttpStatus.OK,
    };
  }

  @Delete('sign-out/:token')
  async singOut(
    @Param('token') token: string,
  ): Promise<ServiceResponseInterface<string>> {
    return {
      message: await this.authService.signOut(token),
      statusCode: HttpStatus.OK,
    };
  }
}
