import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { HmacguardGuard } from './hmacguard/hmacguard.guard';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('users')
  @UseGuards(HmacguardGuard)
  getUsers(@Query('q') q: string): string {
    return 'This will return all users with name: ' + q;
  }
}
