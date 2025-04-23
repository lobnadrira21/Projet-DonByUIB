import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { HeaderFrontComponent } from '../header-front/header-front.component';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-participer-don',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule,HeaderFrontComponent],
  templateUrl: './participer-don.component.html',
  styleUrl: './participer-don.component.scss'
})
export class ParticiperDonComponent implements OnInit {
  form!: FormGroup;
  idDon!: number;

  constructor(
    private fb: FormBuilder,
    private route: ActivatedRoute,
    private authService: AuthService,
    private router: Router,
    private http: HttpClient
  ) {}

  ngOnInit(): void {
    this.idDon = +this.route.snapshot.paramMap.get('id')!;
    this.form = this.fb.group({
      montant: ['', [Validators.required, Validators.min(1)]]
    });
  }

  onSubmit() {
    if (this.form.valid) {
      const montant = this.form.value.montant;
      localStorage.setItem('id_don', this.idDon.toString());
      localStorage.setItem('montant', montant.toString()); 
      this.http.post('http://127.0.0.1:5000/pay-flouci', { amount: montant }, {
        headers: {
          'Authorization': 'Bearer ' + this.authService.getToken(),
          'Content-Type': 'application/json'
        }
      }).subscribe({
        next: (res: any) => {
          if(res.result && res.result.link && res.result.payment_id) {
            localStorage.setItem('payment_id', res.result.payment_id);
            window.location.href = res.result.link;
          } else if(res.link) {
            window.location.href = res.link;
          } else {
            alert("Erreur : lien de paiement Flouci introuvable.");
          }
        },
        error: (err) => {
          alert("Erreur paiement : " + (err.error?.error || "inconnue"));
        }
      });
    }
  }
  
  
  
  
  
  
  

}
