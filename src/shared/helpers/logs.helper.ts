import moment from 'moment';
import { Request } from 'express';
import { config } from '../environments/load-env';

import { createLogger, format, transports } from 'winston';

const { combine, timestamp, printf, colorize } = format;
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} ${level}: ${message}`;
});

const logger = createLogger({
  level: 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    colorize({ all: true }),
    logFormat,
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'combined.log' }),
  ],
});

export class LoggingServiceImpl {
  async error(err: string, req?: Request): Promise<void> {
    const { msLogs, nodeEnv } = config.server;
    const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');

    if (nodeEnv === 'development') {
      console.error(timestamp, 'Error: ', err);
      return;
    }

    if (req?.body?.password) req.body.password = '';
    const log = {
      timestamp,
      microservice: 'MS-AUTHENTICATION',
      type: 'ERROR',
      message: err,
      request: {
        url: req?.originalUrl,
        method: req?.method,
        headers: req?.headers,
        body: req?.body,
        params: req?.params,
        query: req?.query,
      },
    };

    logger.error('Error capturado:', log);
  }
}
