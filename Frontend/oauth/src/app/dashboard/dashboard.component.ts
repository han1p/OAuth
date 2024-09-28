import { Component, OnInit } from '@angular/core';
import { AuthService } from '../auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  template: `
    <div class="dashboard-container">
      <h1>Welcome to the Dashboard</h1>
      <p *ngIf="userInfo">Hello, {{ userInfo.name }}!</p>
      <p>You are successfully logged in!</p>
      <button (click)="logout()">Logout</button>
    </div>
  `,
  styles: [`
    .dashboard-container {
      text-align: center;
      margin-top: 50px;
    }
    h1 {
      font-size: 2.5em;
      margin-bottom: 20px;
    }
    p {
      font-size: 1.2em;
    }
    button {
      font-size: 1.2em;
      padding: 10px 20px;
      margin-top: 20px;
      cursor: pointer;
    }
  `]
})
export class DashboardComponent implements OnInit {
  userInfo: any;  // Declare userInfo variable to hold user data

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit(): void {
    // Check if the user is authenticated
    if (!this.authService.isAuthenticated()) {
      this.router.navigate(['/home']);  // Redirect to home if not authenticated
    } else {
      // Fetch user data if authenticated
      this.authService.getUserInfo().subscribe(
        data => {
          this.userInfo = data;  // Store user info for use in template
        },
        error => {
          console.error('Error fetching user info', error);
          // Optionally, handle error feedback to the user
        }
      );
    }
  }

  // Logout the user and navigate back to the login page
  logout() {
    this.authService.logout();  // This clears tokens and navigates to home
  }
}
