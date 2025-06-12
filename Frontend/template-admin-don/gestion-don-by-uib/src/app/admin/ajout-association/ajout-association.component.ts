import { Component } from '@angular/core';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { HttpClient } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { TypeAssociation } from 'app/models/type-association.model';




@Component({
  selector: 'app-ajout-association',
  standalone: true,
  imports: [RouterModule, 
    CommonModule,
    FormsModule,  // ✅ Required for [(ngModel)]
    MatFormFieldModule,  // ✅ Required for <mat-form-field>
    MatInputModule,  // ✅ Required for matInput
    MatDialogModule,  // ✅ Required for the modal/dialog
    MatButtonModule,  // ✅ Required for buttons
    MatIconModule,
    MatSelectModule  // ✅ Required for Material icons
  ],
  templateUrl: './ajout-association.component.html',
  styleUrl: './ajout-association.component.scss'
})


export class AjoutAssociationComponent {
   typesAssociation: string[] = Object.values(TypeAssociation);
  association = {
    nom_complet: '',
    email: '',
    telephone: '',
    description_association: '',
    adresse: '',
    type_association: '',
    password: '',
    
  };

  constructor(
    public dialogRef: MatDialogRef<AjoutAssociationComponent>,
    private http: HttpClient
  ) {}

  onNoClick(): void {
    this.dialogRef.close();
  }

  isValid(): boolean {
    return Object.values(this.association).every(
  (field) => typeof field === 'string' && field.trim() !== ''
);

  }

  addAssociation(): void {
    if (this.isValid()) {
      const token = localStorage.getItem('token'); // ✅ Retrieve JWT token from local storage
  
      this.http.post('http://localhost:5000/create-association', this.association, {
        headers: { Authorization: `Bearer ${token}` } // ✅ Attach token
      }).subscribe({
        next: (response) => {
          console.log('Success:', response);
          this.dialogRef.close(response);
        },
        error: (error) => {
          console.error('Error:', error);
          if (error.status === 401) {
            alert('Vous devez être connecté pour ajouter une association.');
          } else {
            alert('Erreur lors de la création de l\'association.');
          }
        }
      });
    }
  }
  
}