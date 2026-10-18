import { Controller, Get, HttpStatus } from '@nestjs/common';
import { ServiceResponseI } from 'cms-lib-resources';
import { AppService } from './app.service.js';

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
