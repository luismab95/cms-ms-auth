import moment from 'moment';
import { Request } from 'express';
import { config } from '../environments/load-env';
import { sendRequestPost } from './axios.helper';

export class LoggingServiceImpl {
  async error(err: string, req?: Request): Promise<void> {
    const { msLogs, nodeEnv } = config.server;
    const timestamp = moment().format('YYYY-MM-DD HH:mm:ss');

    if (nodeEnv === 'dev') {
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

    sendRequestPost(`${msLogs}/logs`, log, {
      headers: {
        Authorization: ``,
      },
    });
  }
}
