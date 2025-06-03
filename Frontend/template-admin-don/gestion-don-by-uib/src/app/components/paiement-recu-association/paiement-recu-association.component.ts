import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-paiement-recu-association',
  standalone: true,
  imports: [CommonModule,RouterModule],
  templateUrl: './paiement-recu-association.component.html',
  styleUrl: './paiement-recu-association.component.scss'
})
export class PaiementRecuAssociationComponent implements OnInit {
  paiements: any[] = [];

  constructor(private authService: AuthService, private http: HttpClient) {}

  ngOnInit(): void {
  this.authService.getPaiementsAssociation().subscribe({
    next: (data) => {
      this.paiements = data;
    },
    error: (err) => {
      console.error("Erreur lors du chargement des paiements :", err);
    }
  });
}

downloadRecu(participationId: number) {
  this.authService.getRecuPaiement(participationId).subscribe(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recu_don_${participationId}.pdf`;
    a.click();
    window.URL.revokeObjectURL(url);
  });
}

}

