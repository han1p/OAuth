import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {}

  canActivate(): boolean {
    if (this.authService.isAuthenticated()) {
      console.log("user is logged")
      return true;  // If authenticated, allow access to the route
    } else {
      // If not authenticated, redirect to login
      this.authService.login();
      return false;
    }
  }
}
