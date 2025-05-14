import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { AuthService } from 'app/services/auth.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { FormsModule } from '@angular/forms';




@Component({
  selector: 'app-valider-refuser-don',
  standalone: true,
  imports: [CommonModule,MatSnackBarModule,FormsModule],
  templateUrl: './valider-refuser-don.component.html',
  styleUrl: './valider-refuser-don.component.scss'
})
export class ValiderRefuserDonComponent implements OnInit {
  dons: any[] = [];
  filterStatut: string = 'en_attente';

  constructor(private authService: AuthService, private snackBar: MatSnackBar) {}

  ngOnInit(): void {
    this.loadDons();
  }

  loadDons() {
    this.authService.getAllDonsAdmin().subscribe({
      next: (data) => this.dons = data,
      error: (err) => {
        console.error('Erreur chargement dons', err);
        if (err.status === 403) {
          this.snackBar.open("⛔ Accès refusé. Vous n'êtes pas administrateur.", "Fermer", { duration: 3000 });
        } else if (err.status === 404) {
          this.snackBar.open("❌ Ressource introuvable.", "Fermer", { duration: 3000 });
        } else {
          this.snackBar.open("⚠️ Une erreur est survenue.", "Fermer", { duration: 3000 });
        }
      }
    });
  }

  getDonsFiltres() {
    if (!this.filterStatut) {
      return this.dons;
    }
    return this.dons.filter(d => d.statut?.toLowerCase() === this.filterStatut.toLowerCase());
  }

  valider(id: number) {
    this.authService.validerDon(id).subscribe({
      next: () => {
        this.snackBar.open('✅ Don validé avec succès', 'Fermer', { duration: 3000 });
        this.loadDons();
      },
      error: () => {
        this.snackBar.open('❌ Erreur de validation', 'Fermer', { duration: 3000 });
      }
    });
  }

  refuser(id: number) {
    this.authService.refuserDon(id).subscribe({
      next: () => {
        this.snackBar.open('❌ Don refusé avec succès', 'Fermer', { duration: 3000 });
        this.loadDons();
      },
      error: () => {
        this.snackBar.open('⚠️ Erreur lors du refus', 'Fermer', { duration: 3000 });
      }
    });
  }
  
  
}

