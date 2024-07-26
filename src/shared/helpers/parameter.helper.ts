import { HttpException, HttpStatus } from '@nestjs/common';
import { decryptedData } from './bcrypt.helper';
import { ParameterRepository } from '../repositories/parameter.repository';

export async function getParameter(code: string) {
  const parameterRepository = new ParameterRepository();
  const parameter = await parameterRepository.findParameter(code);

  if (!parameter === undefined) {
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
