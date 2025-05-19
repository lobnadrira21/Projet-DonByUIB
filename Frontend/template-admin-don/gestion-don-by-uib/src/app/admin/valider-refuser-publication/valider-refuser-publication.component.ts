import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-valider-refuser-publication',
  standalone: true,
  imports: [CommonModule,MatSnackBarModule,FormsModule],
  templateUrl: './valider-refuser-publication.component.html',
  styleUrl: './valider-refuser-publication.component.scss'
})
export class ValiderRefuserPublicationComponent implements OnInit {
  publications: any[] = [];
  filterStatut: string = 'en_attente';
  
    constructor(private authService: AuthService, private snackBar: MatSnackBar) {}
  
    ngOnInit(): void {
      this.loadPublications();
    }
  
    loadPublications() {
      this.authService.getAllPublicationAdmin().subscribe({
        next: (data) => this.publications = data,
        error: (err) => {
          console.error('Erreur chargement publications', err);
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
  
    getPublicationFiltres() {
      if (!this.filterStatut) {
        return this.publications;
      }
      return this.publications.filter(d => d.statut?.toLowerCase() === this.filterStatut.toLowerCase());
    }
  
    valider(id: number) {
      this.authService.validerPublication(id).subscribe({
        next: () => {
          this.snackBar.open('✅ Publication validée avec succès', 'Fermer', { duration: 3000 });
          this.loadPublications();
        },
        error: () => {
          this.snackBar.open('❌ Erreur de validation', 'Fermer', { duration: 3000 });
        }
      });
    }

    refuser(id: number) {
    this.authService.refuserPublication(id).subscribe({
      next: () => {
        this.snackBar.open('❌ Publication refusée avec succès', 'Fermer', { duration: 3000 });
        this.loadPublications();
      },
      error: () => {
        this.snackBar.open('⚠️ Erreur lors du refus', 'Fermer', { duration: 3000 });
      }
    });
  }
  
  
    
    

}
