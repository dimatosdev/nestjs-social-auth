import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { SchemaTypes, Types } from "mongoose";

@Schema()
export class User {
    @Prop({type: SchemaTypes.ObjectId, auto: true})
    _id: Types.ObjectId;

    @Prop({unique: true})
    email: String;

    @Prop()
    password: String;
}

export const UserSchema = SchemaFactory.createForClass(User);
