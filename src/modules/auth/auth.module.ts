import { Module } from '@nestjs/common';
import { ParameterRepository } from '@shared/repositories/parameter.repository.js';
import { UserRepository } from '@shared/repositories/user.repository.js';
import { InitializerRepository } from '@shared/repositories/initializate.repository.js';
import { AuthController } from './controllers/auth.controller.js';
import { AuthService } from './services/auth.service.js';
import { AuthRepository } from './repositories/auth.repository.js';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthRepository,
    ParameterRepository,
    UserRepository,
    InitializerRepository,
  ],
})
export class AuthModule {}
