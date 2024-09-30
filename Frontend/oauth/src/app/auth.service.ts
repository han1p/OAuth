import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private username: string | null = null;
  private access_token: string | null = null;

  private apiUrl = 'http://localhost:8000/auth'; // Adjust based on your API URL

  constructor(private http: HttpClient) { }

  // Set the username from a cookie
  setDataFromCookies() {
    const cookies = document.cookie.split('; ');
    const usernameCookie = cookies.find(cookie => cookie.startsWith('username='));
    const access_token = cookies.find(cookie => cookie.startsWith('access_token='))
    console.log(access_token)

    if (usernameCookie) {
      this.username = usernameCookie.split('=')[1];
    }

    if(access_token){
      this.access_token = access_token.split("=")[1];
    }
  }

  // Get the current username
  getUsername(): string | null {
    return this.username;
  }

  // Clear username (for logout)
  clearUsername() {
    this.username = null;
  }

  // Method to check if the user is authenticated
  checkAuthentication(): Observable<any> {
    return this.http.get(`${this.apiUrl}/check`, { withCredentials: true });
  }

  isAuthenticated(){
    return !! this.access_token;
  }
}
