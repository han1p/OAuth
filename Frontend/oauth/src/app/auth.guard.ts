import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from './auth.service'; // Adjust the path to your AuthService
import { of, Observable, map, tap } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> {
    return this.authService.isAuthenticated$.pipe(
      tap(isauthenticated => {
        if(!isauthenticated){
          this.router.navigate(['/login']); // redirect to login if user is not authenticated
        }
      }),
      map(isauthenticated => !!isauthenticated) // return the authentication status as boolean to canActivate
    )
  }
}
