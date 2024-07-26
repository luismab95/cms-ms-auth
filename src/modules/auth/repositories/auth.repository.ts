import { Database } from 'lib-database/src/shared/config/database';
import {
  LoginAttempt,
  OtpUser,
  Session,
  User,
} from 'lib-database/src/entities/public-api';

import {
  LoginAttemptI,
  LoginAuthDto,
  OtpUserI,
  SessionI,
  UserI,
} from '../dto/auth.dto';

export class AuthRepository {
  async findUser(loginAuthDto: LoginAuthDto): Promise<UserI | undefined> {
    const dataSource = Database.getConnection();
    const query = dataSource
      .createQueryBuilder()
      .select([
        'u.id as id',
        'u.email as email',
        'u.firstname as firstname',
        'u.lastname as lastname',
        'u.password as password',
        'u.two_factor_auth as "twoFactorAuth"',
        'u.role_id as "roleId"',
        'u.status as "status"',
        'u.bloqued as "bloqued"',
        'u.terms as "terms"',
      ])
      .from(User, 'u')
      .where(`UPPER(u.email) = UPPER(:email)`, { email: loginAuthDto.email });

    return await query.getRawOne<UserI>();
  }

  async findOtpUser(
    userId: number,
    type: string,
  ): Promise<OtpUserI | undefined> {
    const dataSource = Database.getConnection();
    const query = dataSource
      .createQueryBuilder()
      .select(['o.otp as otp'])
      .from(OtpUser, 'o')
      .where('o.used = :used', { used: false })
      .andWhere('o.type = :type', { type })
      .andWhere('o.user_id = :userId', { userId })
      .orderBy('o.id', 'DESC');

    return await query.getRawOne<OtpUserI>();
  }

  async generateOpt(
    userId: number,
    type: string,
    otp: string,
  ): Promise<string | undefined> {
    const dataSource = Database.getConnection();
    const otpRepository = dataSource.getRepository(OtpUser);
    const result = otpRepository.create({
      userId,
      otp,
      type,
    } as OtpUser);
    const newOtp = await otpRepository.save(result);
    return newOtp.otp;
  }

  async createSession(
    userId: number,
    ipAddress: string,
    info: string,
    token: string,
  ): Promise<SessionI> {
    const dataSource = Database.getConnection();
    const sessionRepository = dataSource.getRepository(Session);
    const result = sessionRepository.create({
      userId,
      ipAddress,
      info,
      token,
    } as Session);
    const newSession = await sessionRepository.save(result);
    return newSession;
  }

  async updatedSession(sessionId: number, status: boolean): Promise<void> {
    const dataSource = Database.getConnection();
    await dataSource
      .createQueryBuilder()
      .update(Session)
      .set({ active: status })
      .where('id = :id', { id: sessionId })
      .execute();
  }

  async updatedOtpUser(
    otp: string,
    userId: number,
    type: string,
  ): Promise<void> {
    const dataSource = Database.getConnection();
    await dataSource
      .createQueryBuilder()
      .update(OtpUser)
      .set({ used: true })
      .where('user_id = :userId', { userId })
      .andWhere('otp = :otp', { otp })
      .andWhere('type = :type', { type })
      .execute();
  }

  async createAttempt(userId: number, attempt: number) {
    const dataSource = Database.getConnection();
    const loginAttemptRepository = dataSource.getRepository(LoginAttempt);
    const result = loginAttemptRepository.create({
      userId,
      attempt,
    } as LoginAttempt);
    return await loginAttemptRepository.save(result);
  }

  async updatedStatusAttempt(userId: number, status: boolean): Promise<void> {
    const dataSource = Database.getConnection();
    await dataSource
      .createQueryBuilder()
      .update(LoginAttempt)
      .set({ status })
      .where('user_id = :userId', { userId })
      .andWhere('status = true')
      .execute();
  }

  async getLastAttempt(userId: number): Promise<LoginAttemptI | undefined> {
    const dataSource = Database.getConnection();
    const query = dataSource
      .createQueryBuilder()
      .select([
        'la.id as "id"',
        'la.attempt as "attempt"',
        'la.user_id as "userId"',
        'la.status as "status"',
      ])
      .from(LoginAttempt, 'la')
      .where(`la.user_id = :userId`, { userId })
      .andWhere('la.status = true')
      .orderBy('la.id', 'DESC');

    return await query.getRawOne<LoginAttemptI>();
  }

  async toggleBloquedUser(userId: number, status: boolean): Promise<void> {
    const dataSource = Database.getConnection();
    await dataSource
      .createQueryBuilder()
      .update(User)
      .set({ bloqued: status })
      .where('id = :userId', { userId })
      .execute();
  }

  async updatedUser(userId: number, user: UserI): Promise<void> {
    const dataSource = Database.getConnection();
    await dataSource
      .createQueryBuilder()
      .update(User)
      .set({ ...user })
      .where('id = :userId', { userId })
      .execute();
  }
}
