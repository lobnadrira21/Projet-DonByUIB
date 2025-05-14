import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { AuthService } from 'app/services/auth.service';



@Component({
  selector: 'app-mes-paiements',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './mes-paiements.component.html',
  styleUrl: './mes-paiements.component.scss'
})
export class MesPaiementsComponent implements OnInit  {
  paiements: any[] = [];

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    this.authService.getMesPaiements().subscribe(data => {
      this.paiements = data;
    });
  }

  generateRecu(paiement: any): void {
    this.authService.getRecuPaiement(paiement.id_participation).subscribe({
      next: (pdfBlob) => {
        const fileURL = URL.createObjectURL(pdfBlob);
        window.open(fileURL);  // Ouvre le PDF dans un nouvel onglet
      },
      error: (err) => {
        console.error("Erreur lors de la récupération du reçu :", err);
      }
    });
  }
  
  

}
