import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { get } from "http";

const getCurrentUserByContext = (ctx: ExecutionContext) => 
ctx.switchToHttp().getRequest().user;

export const CurrentUser = createParamDecorator((data: unknown, ctx: ExecutionContext) => getCurrentUserByContext(ctx));