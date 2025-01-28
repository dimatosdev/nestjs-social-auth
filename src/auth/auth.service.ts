import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcryptjs';
import { User } from 'src/users/schema/users.schema';
import { UsersService } from 'src/users/users.service';
import { TokenPayload } from './models/token-payload.interface';
import { Response } from 'express';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly configService: ConfigService,
        private readonly jwtService: JwtService
    ) {}
    async login(user: User,response: Response) {
        console.log(response)
        const expiresAccessToken = new Date();
        expiresAccessToken.setMilliseconds(
            expiresAccessToken.getTime() + 
                parseInt(this.configService.getOrThrow<string>(
                    'JWT_ACCESS_TOKEN_EXPIRATION_MS'
                )
            )
        );

        const TokenPayload: TokenPayload = {
            userId: user._id.toHexString(),
        };

        const accessToken = this.jwtService.sign(TokenPayload, {
            secret: this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),
            expiresIn: `${this.configService.getOrThrow(
                'JWT_ACCESS_TOKEN_EXPIRATION_MS'
            )}ms`
        });

        response.cookie('Authentication', accessToken, {
            httpOnly: true,
            secure: this.configService.getOrThrow('NODE_ENV') === 'production',
            expires: expiresAccessToken,
        });
    }

    async validateUser(email: string, password: string) {
        try {
            const user = await this.usersService.getUser({
                email,

            });

            const authenticated = await compare(password, user.password);
            if (!authenticated) {
                throw new UnauthorizedException();
            }
            return user;
        } catch (error) {
            throw new UnauthorizedException('Invalid credentials');
        }
    }
}