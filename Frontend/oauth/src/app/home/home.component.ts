import { Component } from '@angular/core';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-home',
  template: `
    <div class="home-container">
      <h1>Login to Your Account</h1>
      <button (click)="login()">Login</button>
    </div>
  `,
  styles: [`
    .home-container {
      text-align: center;
      margin-top: 100px;
    }
    h1 {
      font-size: 2.5em;
      margin-bottom: 20px;
    }
    button {
      font-size: 1.2em;
      padding: 10px 20px;
      cursor: pointer;
    }
  `]
})
export class HomeComponent {

  constructor(private authService: AuthService) {}

  // Start the login process
  login() {
    this.authService.login();  // This will redirect to the backend's login route
  }
}
