import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { config } from './shared/environments/load-env';
import { Database } from 'lib-database/src/shared/config/database';

async function bootstrap() {
  const { port } = config.server;

  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.setGlobalPrefix('ms-auth');

  await app.listen(port);
  await Database.connect();

  console.info(`MS-AUTH iniciado en el puerto: ${port}`);
}
bootstrap();
