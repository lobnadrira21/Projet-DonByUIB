import { Component, OnInit } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { RecaptchaModule } from 'ng-recaptcha';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';


@Component({
  selector: 'app-register',
  standalone: true,
  imports: [RecaptchaModule, CommonModule, FormsModule, RouterModule,MatFormFieldModule,
    MatInputModule,
    MatIconModule,
    MatButtonModule,
    MatCheckboxModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent implements OnInit {
  captcha: string;
  email: string = '';
  password: string = '';
  confirmPassword: string = '';
  nom_complet: string = '';
  telephone: string = '';
  role: string = 'donator'; // Default role
  errorMessage: string = '';
  constructor(private authService: AuthService, private router: Router) {
    this.captcha = '';
   
  }

  ngOnInit(): void {
    // Initialize any necessary logic here if needed
    console.log("RegisterComponent initialized.");
  }
  

  resolved(captchaResponse: string | null) {
    this.captcha = captchaResponse ?? ''; 
    console.log('Resolved captcha with response:', this.captcha);
  }


  register() {
    if (!this.email || !this.password || !this.nom_complet || !this.telephone) {
      this.errorMessage = "All fields are required.";
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.errorMessage = "Passwords do not match.";
      return;
    }

    const userData = {
      email: this.email,
      password: this.password,
      nom_complet: this.nom_complet,
      telephone: this.telephone,
      role: this.role
    };

    this.authService.register(userData).subscribe({
      next: (response) => {
        console.log('Registration successful:', response);
        
        // ✅ Save token & role (if returned from backend)
        if (response.access_token) {
          this.authService.saveToken(response.access_token, response.role, response.username);
        }
  
        // ✅ Redirect based on role
        if (response.role === 'donator') {
          this.router.navigate(['/dashboard-donator']); // Redirect Donators
        } else {
          this.router.navigate(['/login']); // Default redirect if no role
        }
      },
      error: (error) => {
        console.error('Registration failed:', error);
        this.errorMessage = error.error?.error || "An error occurred. Please try again.";
      }
    });
  }
  

  goToHome() {
    this.router.navigate(['/']);
  }
}
