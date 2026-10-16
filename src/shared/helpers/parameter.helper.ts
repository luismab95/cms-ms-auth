import { HttpException, HttpStatus } from '@nestjs/common';
import { ParameterRepository } from '../repositories/parameter.repository.js';
import { decryptedData } from './bcrypt.helper.js';

export async function getParameter(code: string) {
  const parameterRepository = new ParameterRepository();
  const parameter = await parameterRepository.findParameter(code);

  if (!parameter) {
    throw new HttpException(
      `No se encontro el parámetro con código" ${code}`,
      HttpStatus.BAD_GATEWAY,
    );
  }

  if (parameter.private) {
    parameter.value = decryptedData(parameter.value);
  }
  return parameter.value;
}
