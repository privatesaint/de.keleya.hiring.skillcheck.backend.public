import { IsNotEmpty, IsInt, Min } from 'class-validator';

export class DeleteUserDto {
  @IsNotEmpty()
  @IsInt()
  @Min(1)
  public id: number;
}
