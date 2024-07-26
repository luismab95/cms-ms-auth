import { Controller, Get, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { ServiceResponseInterface } from './shared/interfaces/response.interface';
import { OK_200 } from './shared/constants/message.constants';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getIndex(): ServiceResponseInterface<string> {
    return {
      message: this.appService.getIndex(),
      statusCode: HttpStatus.OK,
    };
  }
}
