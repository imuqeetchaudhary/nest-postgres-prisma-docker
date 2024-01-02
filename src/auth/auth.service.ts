import { ConfigService } from '@nestjs/config';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { User } from '@prisma/client';

import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto): Promise<{ access_token: string }> {
    try {
      const hash: string = await argon.hash(dto.password);

      const user: User = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hash,
        },
      });

      delete user.password;

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError)
        if (error.code === 'P2002')
          throw new ForbiddenException('email already exists');
      throw error;
    }
  }

  async signin(dto: AuthDto): Promise<{ access_token: string }> {
    const user: User = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('invalid credentials');

    const pwMatches: boolean = await argon.verify(user.password, dto.password);

    if (!pwMatches) throw new ForbiddenException('invalid credentials');

    delete user.password;

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = { sub: userId, email };

    const access_token: string = await this.jwt.signAsync(payload, {
      expiresIn: this.config.get('JWT_EXPIRY'),
      secret: this.config.get('JWT_SECRET'),
    });

    return {
      access_token,
    };
  }
}
