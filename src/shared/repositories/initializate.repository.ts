import { HttpException, HttpStatus } from '@nestjs/common';
import { Database, EntityManager, Initializer } from 'cms-lib-database';
import { errorQuery, ColumnsEnum } from 'cms-lib-resources';
import { InitializerI } from '@modules/auth/dto/auth.dto.js';

export class InitializerRepository {
  async find(): Promise<Initializer | undefined> {
    const dataSource = Database.getConnection();
    const query = dataSource
      .createQueryBuilder()
      .select([
        'i.id as id',
        'i.hash as hash',
        'i.user_pwd as "userPwd"',
        'i.status as status',
      ])
      .from(Initializer, 'i')
      .where('i.id = :id', { id: 1 });
    return await query.getRawOne<InitializerI>();
  }

  async update(dataSource: EntityManager): Promise<number> {
    try {
      const update = await dataSource
        .createQueryBuilder()
        .update(Initializer)
        .set({ userPwd: true })
        .where('id = :id', { id: 1 })
        .execute();
      return update.affected!;
    } catch (error) {      
      const customMessage = errorQuery(error, ColumnsEnum);
      throw new HttpException(customMessage, HttpStatus.BAD_REQUEST);
    }
  }
}
