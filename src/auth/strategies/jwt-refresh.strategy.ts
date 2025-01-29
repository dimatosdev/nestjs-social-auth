import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { AuthService } from "../auth.service";
import { TokenPayload } from "../models/token-payload.interface";


@Injectable()

export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh'){
    constructor(
        configService: ConfigService, 
        private readonly authService: AuthService){
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (req: Request) => req.cookies?.Refresh,       
            ]),
            secretOrKey: configService.getOrThrow<string>('JWT_REFRESH_TOKEN_SECRET'),
            passReqToCallback: true,
        });
    }

    async validate(req: Request, payload: TokenPayload){
        return this.authService.verifyUserRefreshToken(req.cookies?.Refresh, payload.userId);
    }
}