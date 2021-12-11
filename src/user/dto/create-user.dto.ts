import { IsNotEmpty, IsEmail, IsBoolean, MaxLength, IsOptional, Validate } from 'class-validator';
import { UnencryptedPasswordValidator } from '../../common/validators/unencrypted-password-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @MaxLength(200)
  public name: string;

  @IsNotEmpty()
  @IsEmail()
  @MaxLength(150)
  public email: string;

  @IsNotEmpty()
  @Validate(UnencryptedPasswordValidator)
  public password: string;

  @IsBoolean()
  @IsOptional()
  public is_admin?: boolean;
}
