import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { Request } from "express";
import { ExtractJwt, Strategy } from "passport-jwt";
import { TokenPayload } from "../models/token-payload.interface";
import { UsersService } from "src/users/users.service";
import { Injectable } from "@nestjs/common";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy){
    constructor(
        configService: ConfigService, 
        private readonly usersService: UsersService){
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (req: Request) => req.cookies?.Authentication,       
            ]),
            secretOrKey: configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),

        });
    }
    validate(payload: TokenPayload){
        return this.usersService.getUser({ _id: payload.userId });
    }
}
