import { Injectable, NotFoundException, NotImplementedException, UnauthorizedException } from '@nestjs/common';
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
    throw new NotImplementedException();
  }

  /**
   * Finds single User by id, name or email
   *
   * @param whereUnique
   * @returns User
   */
  async findUnique(whereUnique: Prisma.UserWhereUniqueInput, includeCredentials = false) {
    return this.prisma.user.findUnique({
      where: whereUnique,
      include: { credentials: includeCredentials },
    });
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
    throw new NotImplementedException();
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
    throw new NotImplementedException();
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

    if (!user.credentials) {
      throw new NotFoundException();
    }

    const checkedPassword = await matchHashedPassword(authenticateUserDto.password, user.credentials.hash);

    if (!checkedPassword) {
      throw new UnauthorizedException();
    }

    const token = this.jwtService.sign({
      id: user.id,
      is_staff: user.is_admin,
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

    if (!user.credentials) {
      throw new UnauthorizedException();
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
    throw new NotImplementedException();
  }
}
