import { Parameter, Database } from 'cms-lib-database';
import { ParameterI } from 'cms-lib-resources';

export class ParameterRepository {
  async getParameters(): Promise<ParameterI[]> {
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
      .from(Parameter, 'p');
    return await query.getRawMany<ParameterI>();
  }
}
