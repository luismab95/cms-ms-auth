import { config } from '../environments/load-env';
import { sendRequestPost } from './axios.helper';
import { generateForgotPassword, generateTemporaltToken } from './jwt.helper';

export interface EmailInterface {
  to: string;
  from: string;
  subject: string;
  templateName: string;
  context: any;
}

export const sendMail = async (email: EmailInterface) => {
  const { msEmail } = config.server;
  const token = generateTemporaltToken();
  sendRequestPost(`${msEmail}/email`, email, {
    headers: {
      Authorization: token,
    },
  });
};
