import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  Query,
  Req,
  HttpCode,
  UseGuards,
  NotImplementedException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from 'src/common/decorators/currentUser';

@Controller('user')
export class UserController {
  constructor(private readonly usersService: UserService) {}

  @Get()
  async find(@Query() findUserDto: FindUserDto, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async findUnique(@Param('id', ParseIntPipe) id, @Req() req: Request, @CurrentUser() user) {
    if (!user.is_admin && user.id !== id) {
      throw new UnauthorizedException();
    }
    return this.usersService.findUnique({ id });
  }

  @Post()
  @HttpCode(200)
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Patch()
  async update(@Body() updateUserDto: UpdateUserDto, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Delete()
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async delete(@Body() deleteUserDto: DeleteUserDto, @Req() req: Request, @CurrentUser() user) {
    if (!user.is_admin && user.id !== deleteUserDto.id) {
      throw new UnauthorizedException();
    }
    return this.usersService.delete(deleteUserDto);
  }

  @Post('validate')
  @HttpCode(200)
  async userValidateToken(@Req() req: Request) {
    const token = req.headers['authorization'].split(' ')[1];

    return this.usersService.validateToken(token);
  }

  @Post('authenticate')
  @HttpCode(200)
  async userAuthenticate(@Body() authenticateUserDto: AuthenticateUserDto) {
    return this.usersService.authenticate(authenticateUserDto);
  }

  @Post('token')
  @HttpCode(200)
  async userGetToken(@Body() authenticateUserDto: AuthenticateUserDto) {
    return this.usersService.authenticateAndGetJwtToken(authenticateUserDto);
  }
}
