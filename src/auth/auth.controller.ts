import { Controller, Post, Res, UseGuards } from '@nestjs/common';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { User } from 'src/users/schema/users.schema';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { JwtRefreshAuthGuard } from './guards/jwt-refresh-auth.guards';

@Controller('auth')
export class AuthController {
    constructor (private readonly authService: AuthService) {}

    @Post('login')
    @UseGuards(LocalAuthGuard)
    async login(
      @CurrentUser() user: User,
      @Res({ passthrough: true }) response: Response,
    ) {
        await this.authService.login(user, response);
    }

    @Post('refresh')
    @UseGuards(JwtRefreshAuthGuard) 
    async refreshToken(
        @CurrentUser() user: User,
        @Res({ passthrough: true }) response: Response,
    ) {
      console.log('refresh token');
        await this.authService.login(user, response);
    }
}
