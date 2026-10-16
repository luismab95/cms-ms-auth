import { config } from '../environments/load-env.js';
import { EmailInterface } from '../interfaces/email.interface.js';
import { sendRequestPost } from './axios.helper.js';
import { generateTemporaltToken } from './jwt.helper.js';

export const sendMail = async (email: EmailInterface) => {
  const { msEmail } = config.server;
  const token = generateTemporaltToken();
  sendRequestPost(`${msEmail}/email`, email, {
    headers: {
      Authorization: token,
    },
  });
};
