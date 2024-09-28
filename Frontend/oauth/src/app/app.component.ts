import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './auth.service';

@Component({
    selector: 'app-root',
    templateUrl: './app.component.html',
    styleUrls: ['./app.component.css']
})
export class AppComponent {
    constructor(private authService: AuthService, private router: Router) {
        // Check if the user is authenticated on app start
        this.authService.checkAuth().subscribe(
            (response) => {
                // Assuming response returns a boolean or a user object
                if (response.isAuthenticated) {
                    this.router.navigate(['/dashboard']); // Navigate to dashboard if authenticated
                } else {
                    this.router.navigate(['/']); // Otherwise navigate to home
                }
            },
            (error) => {
                console.error('Error checking authentication:', error);
                this.router.navigate(['/']); // Navigate to home on error
            }
        );
    }
}
