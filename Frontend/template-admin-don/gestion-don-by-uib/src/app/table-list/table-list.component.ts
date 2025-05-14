import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { AjoutDonComponent } from 'app/components/ajout-don/ajout-don.component';

@Component({
  selector: 'app-table-list',
  standalone: true,
  templateUrl: './table-list.component.html',
  styleUrls: ['./table-list.component.css'],
  imports: [MatButtonModule, MatTooltipModule,RouterModule, CommonModule,
     FormsModule,  // ✅ Required for [(ngModel)]
        MatFormFieldModule,  // ✅ Required for <mat-form-field>
        MatInputModule,  // ✅ Required for matInput
        MatDialogModule,  // ✅ Required for the modal/dialog
          // ✅ Required for buttons
        MatIconModule,
        ReactiveFormsModule

        
  ],

})
export class TableListComponent implements OnInit {

  dons: any[] = [];
  

  constructor(
    private authService: AuthService,
 
    private http: HttpClient,
    private dialog: MatDialog
  ) {
  
  }

  ngOnInit(): void {
    this.authService.getDons().subscribe({
      next: (data) => this.dons = data,
      error: (err) => console.error('❌ Erreur lors du chargement des dons', err)
    });
  }
  openAddDonModal(): void {
    const dialogRef = this.dialog.open(AjoutDonComponent, {
      width: '700px',
      disableClose: true
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        console.log('✅ Don ajouté:', result);
        // Optionally refresh the list of dons here
        this.authService.getDons().subscribe(dons => this.dons = dons);
      }
    });
  }

  deleteDon(id: number) {
    if (confirm("Êtes-vous sûr de vouloir supprimer ce don ?")) {
      this.authService.deleteDon(id).subscribe({
        next: (res) => {
          console.log(res.message);
          this.authService.getDons(); 
        },
        error: (err) => {
          console.error("Erreur de suppression :", err);
        }
      });
    }
  }

}
