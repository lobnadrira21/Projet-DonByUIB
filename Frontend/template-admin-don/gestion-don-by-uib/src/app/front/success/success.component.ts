import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-success',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './success.component.html',
  styleUrl: './success.component.scss'
})
export class SuccessComponent implements OnInit {

  paymentStatus: string = '';
  loading: boolean = true;

  constructor(
    private route: ActivatedRoute,
    private http: HttpClient
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      let paymentId = params['payment_id'];
      // Si pas dans l'URL, essayer de le récupérer depuis localStorage
      if (!paymentId) {
        paymentId = localStorage.getItem('payment_id') || '';
      }
      if (paymentId) {
        this.http.get('http://127.0.0.1:5000/verify-flouci-payment/' + paymentId)
          .subscribe({
            next: (res: any) => {
              this.loading = false;
              if(res.success && res.result.status === "SUCCESS") {
                this.paymentStatus = 'Paiement confirmé ! Merci pour votre don.';
              } else {
                this.paymentStatus = 'Paiement non confirmé. Veuillez contacter le support.';
              }
              // (Optionnel) nettoyer le localStorage pour éviter les confusions
              localStorage.removeItem('payment_id');
            },
            error: () => {
              this.loading = false;
              this.paymentStatus = 'Erreur lors de la vérification du paiement.';
            }
          });
      } else {
        this.loading = false;
        this.paymentStatus = 'Aucun identifiant de paiement fourni.';
      }
    });
  }

}
