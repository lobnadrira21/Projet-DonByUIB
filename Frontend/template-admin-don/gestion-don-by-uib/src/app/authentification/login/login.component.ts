import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatIconModule } from '@angular/material/icon';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule,HttpClientModule, RouterModule,MatIconModule], 
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
  providers: [AuthService]
})
export class LoginComponent  implements OnInit  {
  email: string = '';
  password: string = '';
  errorMessage: string = '';
  // private clientId = "841926294712-fqfpta7nvuf8t90r396fiaa6je9qagsh.apps.googleusercontent.com";
  constructor(private authService: AuthService, private router: Router) {}
  login(): void {
    this.authService.login(this.email, this.password).subscribe({
      next: (response) => {
        console.log('Login Successful:', response);
  
        this.authService.saveToken(response.access_token, response.role, response.username); // ✅ Store role
  
        // 🚀 Redirect based on role
        if (response.role === 'admin') {
          this.router.navigate(['/dashboard']);
        } else if (response.role === 'association') {
          this.router.navigate(['/dashboard-association']);
        } else if (response.role === 'donator') {
          this.router.navigate(['/dashboard-donator']);
        } else {
          console.error('Access denied.');
          this.errorMessage = 'Access denied.';
        }
      },
      error: (error) => {
        console.error('Login Failed:', error);
        this.errorMessage = 'Invalid credentials. Please try again.';
      }
    });
  }
  
  
 
    ngOnInit() {
      
    }
  
    
  
    /** Navigate to home page */
    goToHome() {
      this.router.navigate(['/']);
    }
  }