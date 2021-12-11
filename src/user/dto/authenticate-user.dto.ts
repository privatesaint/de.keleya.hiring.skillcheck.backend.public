import { IsNotEmpty, IsEmail, Validate } from 'class-validator';
import { UnencryptedPasswordValidator } from '../../common/validators/unencrypted-password-validator';

export class AuthenticateUserDto {
  @IsNotEmpty()
  @IsEmail()
  public email: string;

  @IsNotEmpty()
  @Validate(UnencryptedPasswordValidator)
  public password: string;
}
