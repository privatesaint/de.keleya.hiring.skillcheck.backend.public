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
} from '@nestjs/common';
import { Request } from 'express';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly usersService: UserService) {}

  @Get()
  async find(@Query() findUserDto: FindUserDto, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Get(':id')
  async findUnique(@Param('id', ParseIntPipe) id, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Post()
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Patch()
  async update(@Body() updateUserDto: UpdateUserDto, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Delete()
  async delete(@Body() deleteUserDto: DeleteUserDto, @Req() req: Request) {
    throw new NotImplementedException();
  }

  @Post('validate')
  async userValidateToken(@Req() req: Request) {
    throw new NotImplementedException();
  }

  @Post('authenticate')
  async userAuthenticate(@Body() authenticateUserDto: AuthenticateUserDto) {
    throw new NotImplementedException();
  }

  @Post('token')
  async userGetToken(@Body() authenticateUserDto: AuthenticateUserDto) {
    return this.usersService.authenticateAndGetJwtToken(authenticateUserDto);
  }
}
