import { Component, OnInit } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AuthService } from 'app/services/auth.service';
import { ChangeDetectorRef } from '@angular/core';
import { AjoutAssociationComponent } from '../ajout-association/ajout-association.component';
import { MatDialog } from '@angular/material/dialog';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-gestion-users',
  standalone: true,
  imports: [CommonModule,MatButtonModule, MatTooltipModule,RouterModule],
  templateUrl: './gestion-users.component.html',
  styleUrl: './gestion-users.component.scss'
})
export class GestionUsersComponent implements OnInit {
  associations: any[] = [];

  constructor(private authService: AuthService, private cdRef: ChangeDetectorRef,public dialog: MatDialog) {}

  ngOnInit() {
    this.loadAssociations();
  }

  loadAssociations(): void {
    console.log("📡 Appel API getAssociations...");
    this.authService.getAssociations().subscribe({
      next: (data) => {
        console.log("✅ Associations reçues :", data);
        this.associations = Array.isArray(data) ? data : [];
        this.cdRef.detectChanges(); // 👈 Forcer l'affichage dans l'interface
      },
      error: (err) => {
        console.error("❌ Erreur lors du chargement :", err);
      }
    });
  }
  
  




  openAddAssociationModal(): void {
    const dialogRef = this.dialog.open(AjoutAssociationComponent, {
      width: '600px',
      disableClose: true
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        console.log('New Association:', result);
      }
    });
  }
}
