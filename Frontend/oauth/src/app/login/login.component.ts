import { Component } from '@angular/core';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {

  // This function will trigger when the user clicks the login button
  login() {
    window.location.href = 'http://localhost:8000/auth/login/';
  }
  
}
