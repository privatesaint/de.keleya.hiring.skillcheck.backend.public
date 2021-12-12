import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma, User } from '@prisma/client';
import { PrismaService } from '../prisma.services';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { hashPassword, matchHashedPassword } from '../common/utils/password';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService, private readonly jwtService: JwtService) {}

  /**
   * Finds users with matching fields
   *
   * @param findUserDto
   * @returns User[]
   */
  async find(findUserDto: FindUserDto): Promise<User[]> {
    let users;

    let ids = [];

    if (findUserDto.id && Array.isArray(findUserDto.id)) {
      ids = findUserDto.id.map((id) => Number(id));
    }

    if (findUserDto.name) {
      const userIds = await this.prisma.$queryRawUnsafe<{ id: number }[]>(
        'SELECT id FROM "users" WHERE name LIKE $1',
        `%${findUserDto.name}%`,
      );
      const foundUsers = userIds.map((row) => row.id);

      ids.push(...foundUsers);
    }

    const query = { where: {}, include: { credentials: false } };
    if (findUserDto.offset) {
      query['skip'] = Number(findUserDto.offset);
    }

    if (findUserDto.limit) {
      query['take'] = Number(findUserDto.limit);
    }

    if (findUserDto.email) {
      query.where['email'] = { equals: findUserDto.email };
    }

    if (findUserDto.credentials == 'true') {
      query.include.credentials = true;
    }

    if (findUserDto.name || findUserDto.id) {
      typeof findUserDto.id === 'string' && ids.push(Number(findUserDto.id));

      query.where['id'] = { in: ids };
    }

    if (findUserDto.updatedSince) {
      query.where['updated_at'] = { gte: new Date(findUserDto.updatedSince) };
    }

    users = await this.prisma.user.findMany(query);

    return users;
  }

  /**
   * Finds single User by id, name or email
   *
   * @param whereUnique
   * @returns User
   */
  async findUnique(whereUnique: Prisma.UserWhereUniqueInput, includeCredentials = false) {
    const user = await this.prisma.user.findUnique({
      where: whereUnique,
      include: { credentials: includeCredentials },
    });

    if (!user) {
      throw new NotFoundException();
    }

    return user;
  }

  /**
   * Creates a new user with credentials
   *
   * @param createUserDto
   * @returns result of create
   */
  async create(createUserDto: CreateUserDto) {
    const hashedPassword = await hashPassword(createUserDto.password);

    return this.prisma.user.create({
      data: {
        name: createUserDto.name,
        email: createUserDto.email,
        is_admin: createUserDto.is_admin,

        credentials: {
          create: {
            hash: hashedPassword,
          },
        },
      },
    });
  }

  /**
   * Updates a user unless it does not exist or has been marked as deleted before
   *
   * @param updateUserDto
   * @returns result of update
   */
  async update(updateUserDto: UpdateUserDto) {
    const user = await this.findUnique({ id: updateUserDto.id });

    if (user.name === '(deleted)') {
      throw new NotFoundException();
    }

    let data;
    data = {
      name: updateUserDto.name,
      email: updateUserDto.email,
      email_confirmed: updateUserDto.email_confirmed,
      is_admin: updateUserDto.is_admin,
    };

    if (updateUserDto.password) {
      const hashedPassword = await hashPassword(updateUserDto.password);
      data.credentials = {
        update: {
          hash: hashedPassword,
        },
      };
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: updateUserDto.id },
      data,
    });

    return {
      ...updatedUser,
      createdAt: updatedUser.created_at,
      updatedAt: updatedUser.updated_at,
    };
  }

  /**
   * Deletes a user
   * Function does not actually remove the user from database but instead marks them as deleted by:
   * - removing the corresponding `credentials` row from your db
   * - changing the name to DELETED_USER_NAME constant (default: `(deleted)`)
   * - setting email to NULL
   *
   * @param deleteUserDto
   * @returns results of users and credentials table modification
   */
  async delete(deleteUserDto: DeleteUserDto) {
    const user = await this.findUnique({ id: deleteUserDto.id });

    if (user.name === '(deleted)') {
      throw new NotFoundException();
    }

    const deletedUser = await this.prisma.user.update({
      where: { id: deleteUserDto.id },
      data: {
        name: '(deleted)',
        email: null,
        credentials: {
          delete: true,
        },
      },
    });

    return { users: deletedUser };
  }

  /**
   * Authenticates a user and returns a JWT token
   *
   * @param authenticateUserDto email and password for authentication
   * @returns a JWT token
   */
  async authenticateAndGetJwtToken(authenticateUserDto: AuthenticateUserDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: authenticateUserDto.email },
      include: { credentials: true },
    });

    if (!user || !user.credentials) {
      throw new NotFoundException();
    }

    const checkedPassword = await matchHashedPassword(authenticateUserDto.password, user.credentials.hash);

    if (!checkedPassword) {
      throw new UnauthorizedException();
    }

    const token = this.jwtService.sign({
      id: user.id,
      username: user.email,
    });

    return { token };
  }

  /**
   * Authenticates a user
   *
   * @param authenticateUserDto email and password for authentication
   * @returns true or false
   */
  async authenticate(authenticateUserDto: AuthenticateUserDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: authenticateUserDto.email },
      include: { credentials: true },
    });

    if (!user || !user.credentials) {
      throw new NotFoundException();
    }

    const checkedPassword = await matchHashedPassword(authenticateUserDto.password, user.credentials.hash);

    return { credentials: checkedPassword };
  }

  /**
   * Validates a JWT token
   *
   * @param token a JWT token
   * @returns the decoded token if valid
   */
  async validateToken(token: string) {
    try {
      await this.jwtService.verifyAsync(token);

      return { valid: true };
    } catch (e) {
      return { valid: false };
    }
  }
}
