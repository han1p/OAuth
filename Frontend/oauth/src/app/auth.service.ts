import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { AuthCheckResponse } from './interfaces/authcheck.interface';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private apiUrl = 'http://localhost:8000/auth'; // API url

  // A behaviour subject to store the user's auth status
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false);
  isAuthenticated$ = this.isAuthenticatedSubject.asObservable();

  private usernameSubject = new BehaviorSubject<string | null>(null); // BehaviorSubjects stores latest value and ensures the latest value is always available to anyone who subscribes
  username$ = this.usernameSubject.asObservable(); // asObservable() turns the Behaviour subject into a read-only

  constructor(private http: HttpClient) { }

  // Method to check if the user is authenticated
  checkAuthentication(): Observable<AuthCheckResponse> {
    return this.http.get<AuthCheckResponse>(`${this.apiUrl}/check`, { withCredentials: true }).pipe(
      tap(response => {
        if(response.authenticated){
          this.isAuthenticatedSubject.next(true);
          this.usernameSubject.next(response.username);
        } else{
          this.isAuthenticatedSubject.next(false);
          this.usernameSubject.next(null);
        }
      })
    );
  }
}
