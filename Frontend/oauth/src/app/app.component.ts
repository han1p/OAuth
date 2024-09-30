import { Component, OnInit } from '@angular/core';
import { AuthService } from './auth.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit {
  isLoggedIn: boolean = false;
  username: string | null = null

  constructor(private authService: AuthService) {}

  ngOnInit() {
    this.authService.setDataFromCookies();
    this.username = this.authService.getUsername();

    this.authService.checkAuthentication().subscribe({
      next: (response) => {
        this.isLoggedIn = response.authenticated;
        this.username = response.user; // Assuming the backend returns the username
      },
      error: () => {
        // Handle error - user is not authenticated
        this.isLoggedIn = false;
        this.username = null;
      }
    });
  }
}
