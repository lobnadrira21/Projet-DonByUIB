import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { AuthService } from 'app/services/auth.service';
import { CommonModule } from '@angular/common';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
@Component({
  selector: 'app-ajout-don',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule
  ],
  templateUrl: './ajout-don.component.html',
  styleUrl: './ajout-don.component.scss'
})
export class AjoutDonComponent {
  donForm: FormGroup;
  selectedFile: File | null = null;

  constructor(
    private fb: FormBuilder,
    private http: HttpClient,
    private authService: AuthService,
    private dialogRef: MatDialogRef<AjoutDonComponent>  // ✅ pour fermer le modal après ajout
  ) {
    this.donForm = this.fb.group({
      titre: [''],
      description: [''],
      objectif: [''],  // ✅ champ mis à jour
      date_fin_collecte: [''],
    
    });
  }

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0];
  }

  ajouterDon() {
    const formData = new FormData();
    Object.entries(this.donForm.value).forEach(([key, val]) => {
      if (val !== null && val !== undefined) {
        formData.append(key, val.toString());
      }
    });

    if (this.selectedFile) {
      formData.append('photo_file', this.selectedFile);
    }

    const headers = new HttpHeaders({
      Authorization: `Bearer ${this.authService.getToken()}`
    });

    this.http.post('http://127.0.0.1:5000/create-don', formData, { headers }).subscribe({
      next: (response) => {
        console.log('✅ Don ajouté avec succès:', response);
        this.dialogRef.close(true);
      },
      error: (err) => {
        console.error('❌ Erreur lors de l’ajout du don:', err);
      }
    });
  }

  onCancel(): void {
    this.dialogRef.close(false);
  }
}
