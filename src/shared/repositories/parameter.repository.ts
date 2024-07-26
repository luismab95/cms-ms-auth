import { Parameter } from 'lib-database/src/entities/public-api';
import { Database } from 'lib-database/src/shared/config/database';
import { ParameterI } from 'src/shared/interfaces/parameter.interface';

export class ParameterRepository {
  async findParameter(code: string): Promise<ParameterI | undefined> {
    const dataSource = Database.getConnection();
    const query = dataSource
      .createQueryBuilder()
      .select([
        'p.id as id',
        'p.code as code',
        'p.name as name',
        'p.description as description',
        'p.value as value',
        'p.private as "private"',
      ])
      .from(Parameter, 'p')
      .where('p.code = :code', { code: code });
    return await query.getRawOne<ParameterI>();
  }
}
