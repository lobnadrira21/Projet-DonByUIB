import { CommonModule } from '@angular/common';
import { HttpClient, HttpClientModule,HttpHeaders } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';

@Component({
  selector: 'app-change-password',
  standalone: true,
  imports: [CommonModule,
      FormsModule,       
      RouterModule,       
      HttpClientModule,
      ],
  templateUrl: './change-password.component.html',
  styleUrl: './change-password.component.scss'
})
export class ChangePasswordComponent implements OnInit {
  newPassword: string = '';
  message: string = '';
  errorMessage: string = '';
  token: string | null = null;

  constructor(private route: ActivatedRoute, private http: HttpClient, private router: Router) {}

  ngOnInit() {
    this.token = this.route.snapshot.paramMap.get('token');
    console.log("🎯 Token reçu :", this.token);
  }

  resetPassword() {
    if (!this.token) {
      this.errorMessage = "Token manquant.";
      return;
    }
  
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json'
    });
  
    this.http.post(
      'http://localhost:5000/reset-password',
      { new_password: this.newPassword },
      { headers }
    ).subscribe({
      next: (res: any) => {
        this.message = res.message;
        this.errorMessage = '';
      },
      error: err => {
        this.errorMessage = err.error?.msg || err.error?.error || 'Erreur';
        console.error("Reset error:", err);
      }
    });
  }
  
  
      
  
  
}
