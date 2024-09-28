import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8000/auth';  // Backend API URL

  constructor(private http: HttpClient, private router: Router) {}

  // Initiate OAuth login
  login() {
    // Redirects to the backend login page for OAuth
    window.location.href = `${this.apiUrl}/login/`;  
  }

  // Check if the user is authenticated based on the backend response
  checkAuth(): Observable<any> {
    return this.http.get(`${this.apiUrl}/check_authentication/`, { withCredentials: true });  
  }

  // Check if access_token exists locally for UX
  isAuthenticated(): boolean {
    return !!localStorage.getItem('access_token');  // Local check for UX improvement
  }

  // Logout the user and clear tokens
  logout() {
    localStorage.removeItem('access_token');
    this.router.navigate(['/home']);  // Redirect to home page
  }

  // Optionally add a method to retrieve user information
  getUserInfo(): Observable<any> {
    return this.http.get(`${this.apiUrl}/user/`, { withCredentials: true });
  }
}
