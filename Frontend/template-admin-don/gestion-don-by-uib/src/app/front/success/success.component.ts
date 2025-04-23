import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-success',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './success.component.html',
  styleUrl: './success.component.scss'
})
export class SuccessComponent implements OnInit {

  paymentStatus: string = '';
  loading: boolean = true;

  constructor(
    private route: ActivatedRoute,
    private http: HttpClient,
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      let paymentId = params['payment_id'];
      if (!paymentId) {
        paymentId = localStorage.getItem('payment_id') || '';
      }
      if (paymentId) {
        this.http.get('http://127.0.0.1:5000/verify-flouci-payment/' + paymentId)
          .subscribe({
            next: (res: any) => {
              this.loading = false;
              if (res.success && res.result.status === "SUCCESS") {
                this.paymentStatus = 'Paiement confirmé ! Merci pour votre don.';
                // Enregistrer la participation APRÈS succès paiement
                const idDon = localStorage.getItem('id_don');
                const montant = localStorage.getItem('montant');
                if (idDon && montant) {
                  this.authService.participatedons(+idDon, { montant: +montant }).subscribe({
                    next: () => {
                      // Participation enregistrée, on vide les valeurs
                      localStorage.removeItem('id_don');
                      localStorage.removeItem('montant');
                    },
                    error: (err) => {
                      console.error('Erreur lors de la participation:', err);
                    }
                  });
                }
                setTimeout(() => {
                  window.location.href = '/';
                }, 2000);
              } else {
                this.paymentStatus = 'Paiement non confirmé. Veuillez contacter le support.';
              }
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
