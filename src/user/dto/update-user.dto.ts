import { IsNotEmpty, IsInt, Min, IsEmail, IsBoolean, MaxLength, IsOptional, Validate } from 'class-validator';
import { UnencryptedPasswordValidator } from '../../common/validators/unencrypted-password-validator';

export class UpdateUserDto {
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  public id: number;

  @IsOptional()
  @MaxLength(200)
  public name?: string;

  @IsOptional()
  @Validate(UnencryptedPasswordValidator)
  public password?: string;

  @IsOptional()
  @IsEmail()
  @MaxLength(150)
  public email?: string;

  @IsBoolean()
  @IsOptional()
  public email_confirmed?: boolean;

  @IsBoolean()
  @IsOptional()
  public is_admin?: boolean;
}
