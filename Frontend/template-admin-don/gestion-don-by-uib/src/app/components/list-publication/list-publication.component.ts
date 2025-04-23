import { CommonModule } from '@angular/common';
import { Component, NgModule, OnInit } from '@angular/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { AuthService } from 'app/services/auth.service';
import { Router, RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { AjoutPublicationComponent } from '../ajout-publication/ajout-publication.component';
import { DetailPublicationComponent } from '../detail-publication/detail-publication.component';

@Component({
  selector: 'app-list-publication',
  standalone: true,
  imports: [
    RouterModule,
    CommonModule,
    MatFormFieldModule,
    MatInputModule,
    MatIconModule,
    MatButtonModule,
    CommonModule
  ],
  
  templateUrl: './list-publication.component.html',
  styleUrl: './list-publication.component.scss'
})
export class ListPublicationComponent implements OnInit{
  publications: any[] = [];
  constructor(private authservice: AuthService, private router: Router, private dialog: MatDialog){}
  ngOnInit(): void {
    this.getMyPublications();
  }
  getMyPublications(): void {
    this.authservice.getPublications().subscribe({
      next: (data) => {
        this.publications = data;
      },
      error: (err) => {
        console.error("Erreur chargement publications :", err);
      }
    });
  }

  openAddPublicationDialog(): void {
    const dialogRef = this.dialog.open(AjoutPublicationComponent, {
      width: '600px',
      disableClose: true
    });
  
    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.getMyPublications(); // rafraîchir la liste
      }
    });
  }
  openDetailPublication(id: number): void {
    this.dialog.open(DetailPublicationComponent, {
      width: '600px',
      data: { id }
    });
  }

  modifierPublication(id: number): void {
    this.router.navigate(['/dashboard-association/modifier-publication', id]);
  }

  deletePublication(id: number) {
    if (confirm("Êtes-vous sûr de vouloir supprimer cette publication ?")) {
      this.authservice.deletePublication(id).subscribe({
        next: (res) => {
          console.log(res.message);
          this.getMyPublications(); // 🔄 Recharge la liste après suppression
        },
        error: (err) => {
          console.error("Erreur de suppression :", err);
        }
      });
    }
  }
  
}
