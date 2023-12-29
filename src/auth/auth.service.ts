import { Injectable } from '@nestjs/common';

@Injectable({})
export class AuthService {
  signup() {
    return { message: "I'm signed up" };
  }

  signin() {
    return { message: "I'm signed in" };
  }
}
