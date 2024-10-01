import { Component, OnInit } from '@angular/core';
import { AuthService } from './auth.service'; // Adjust the path as needed
import { take } from 'rxjs/operators';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  isAuthenticated: boolean = false; // Local variable for authentication status
  username: string | null = null; // Local variable for username

  constructor(private authService: AuthService) { }

  ngOnInit(): void {
    // Call checkAuthentication() to fetch the initial authentication status
    this.authService.checkAuthentication().subscribe({
      next: () => {
        // After the initial check, subscribe to the BehaviorSubjects for ongoing updates
        this.authService.isAuthenticated$.subscribe(isAuthenticated => {
          this.isAuthenticated = isAuthenticated; // Update local variable on change
        });

        this.authService.username$.subscribe(username => {
          this.username = username; // Update local variable on change
        });
      },
      error: (err) => {
        console.error('Error checking authentication:', err);
      }
    });
  }
}
