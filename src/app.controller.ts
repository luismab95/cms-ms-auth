import { Controller, Get, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service.js';
import { ServiceResponseI } from '@shared/interfaces/response.interface.js';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  async getIndex(): Promise<ServiceResponseI<string>> {
    return {
      message: this.appService.getIndex(),
      statusCode: HttpStatus.OK,
    };
  }
}
