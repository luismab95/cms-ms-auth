import { RandomEnum } from '../enums/random.enum';

export function randomCharacters(
  option: 'NUMBER' | 'LETTER' | 'COMBINED',
  lengthPass = 6,
) {
  try {
    let pwdChars: string = '';
    switch (option) {
      case 'NUMBER':
        pwdChars = RandomEnum.NUMBER;
        break;
      case 'LETTER':
        pwdChars = RandomEnum.LETTER;
        break;
      case 'COMBINED':
        pwdChars = RandomEnum.COMBINED;
        break;
    }
    const pwdLen = lengthPass;
    const randPassword = Array(pwdLen)
      .fill(pwdChars)
      .map(function (x) {
        return x[Math.floor(Math.random() * x.length)];
      })
      .join('');
    return randPassword;
  } catch (error) {
    return 'q0_1234_ab2q';
  }
}
