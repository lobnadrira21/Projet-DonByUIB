import { CommonModule } from '@angular/common';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [CommonModule,
    FormsModule,       
    RouterModule,       
    HttpClientModule],
  templateUrl: './reset-password.component.html',
  styleUrl: './reset-password.component.scss'
})
export class ResetPasswordComponent implements OnInit {
  email: string = '';
  newPassword: string = '';
  message: string = '';
  errorMessage: string = '';
  error: string = '';

  token: string | null = null;

  constructor(private http: HttpClient, private router: Router,private route: ActivatedRoute) {}
  ngOnInit()  {
    const tokenFromURL = this.route.snapshot.paramMap.get('token');
  if (tokenFromURL) {
    this.token = tokenFromURL;
  }
  }

  requestReset() {
    this.http.post('http://localhost:5000/request-password-reset', { email: this.email }).subscribe({
      next: (res: any) => {
        this.message = res.message;
        this.errorMessage = '';
      },
      error: err => {
        this.errorMessage = err.error?.error || 'Une erreur est survenue.';
        this.message = '';
      }
    });
  }

}
