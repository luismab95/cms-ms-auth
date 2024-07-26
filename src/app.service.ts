import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getIndex(): string {
    return 'Bienvenido/a, pero no hay nada que ver aquí!';
  }
}
