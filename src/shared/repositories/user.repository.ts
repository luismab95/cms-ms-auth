import { HttpException, HttpStatus } from '@nestjs/common';
import { Database, EntityManager, Role, User } from 'cms-lib-database';
import { ColumnsEnum, errorQuery } from 'cms-lib-resources';
import { InitialUserI, UserEmailDto } from '@modules/auth/dto/auth.dto.js';

export class UserRepository {
  async update(user: UserEmailDto, dataSource: EntityManager): Promise<number> {
    try {
      const update = await dataSource
        .createQueryBuilder()
        .update(User)
        .set({ email: user.email, password: user.password })
        .where('id = :id', { id: user.id })
        .execute();
      return update.affected!;
    } catch (error) {
      const customMessage = errorQuery(error, ColumnsEnum);
      throw new HttpException(customMessage, HttpStatus.BAD_REQUEST);
    }
  }

  async get(): Promise<InitialUserI[]> {
    const dataSource = Database.getConnection();
    return await dataSource
      .createQueryBuilder()
      .select([
        'u.id as "id"',
        'u.email as email',
        'u.role_id as "roleId"',
        'r.code as "roleCode"',
        'r.name as "roleName"',
        'r.description as "roleDescription"',
      ])
      .from(User, 'u')
      .innerJoin(Role, 'r', 'r.id = u.role_id')
      .getRawMany<InitialUserI>();
  }
}
