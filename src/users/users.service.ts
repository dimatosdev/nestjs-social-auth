import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/users.schema';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { hash } from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async createUser(createUserDto: CreateUserDto) {
    await new this.userModel({
      ...CreateUserDto, 
      password: await hash(createUserDto.password, 10)
    }).save();
  }

  async getUser(query: FilterQuery<User>) {
    const user = (await this.userModel.findOne(query)).toObject();
    if(!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async updateUser(query: FilterQuery<User>, updateUserDto: UpdateQuery<User>) {
    return this.userModel.findOneAndUpdate (query, updateUserDto);
  }

  
  async getOrCreateUser(createUserDto: CreateUserDto) {
    const user = await this.userModel.findOne({ email: createUserDto.email });
    if (user) {
      return user;
    }
    return this.createUser(createUserDto);

  }
}
