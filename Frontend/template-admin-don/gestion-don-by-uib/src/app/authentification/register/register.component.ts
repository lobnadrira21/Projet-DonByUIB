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
  this.errorMessage = '';

  if (!this.email || !this.password || !this.nom_complet || !this.telephone) {
    this.errorMessage = "Tous les champs sont requis.";
    return;
  }

  if (!this.isValidNomComplet()) {
    this.errorMessage = "Le nom complet doit contenir au maximum 40 caractères.";
    return;
  }
  if (!this.isValidEmail()) {
  this.errorMessage = "L'adresse email n'est pas valide.";
  return;
}


  if (!this.isValidTelephone()) {
    this.errorMessage = "Le numéro de téléphone doit comporter exactement 8 chiffres.";
    return;
  }

  if (!this.isStrongPassword()) {
    this.errorMessage = "Le mot de passe doit contenir une majuscule, un chiffre et un caractère spécial.";
    return;
  }

  if (this.password !== this.confirmPassword) {
    this.errorMessage = "Les mots de passe ne correspondent pas.";
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
      if (response.access_token) {
        this.authService.saveToken(response.access_token, response.role, response.username);
      }

      if (response.role === 'donator') {
        this.router.navigate(['/dashboard-donator']);
      } else {
        this.router.navigate(['/login']);
      }
    },
    error: (error) => {
      console.error('Registration failed:', error);
      this.errorMessage = error.error?.error || "Une erreur est survenue.";
    }
  });
}

  

  goToHome() {
    this.router.navigate(['/']);
  }


 isValidNomComplet(): boolean {
  const regex = /^[A-Za-zÀ-ÿ\s\-]{1,40}$/;
  return regex.test(this.nom_complet);
}

isValidEmail(): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(this.email);
}

hideTelError: boolean = false;

isValidTelephone(): boolean {
  const phoneRegex = /^\d{8}$/;
  return phoneRegex.test(this.telephone);
}



hidePwdError: boolean = false;

isStrongPassword(): boolean {
  const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
  return regex.test(this.password);
}


}
