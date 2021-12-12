import { IsOptional, IsString, IsEmail } from 'class-validator';

export class FindUserDto {
  @IsOptional()
  public limit?: number;

  @IsOptional()
  public offset?: number;

  @IsOptional()
  public updatedSince?: string;

  @IsOptional()
  public id?: number[];

  @IsOptional()
  @IsString()
  public name?: string;

  @IsOptional()
  @IsString()
  public credentials?: string;

  @IsOptional()
  @IsString()
  @IsEmail()
  public email?: string;
}
