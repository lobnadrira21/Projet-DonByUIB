import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-ajout-publication',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule
  ],
  templateUrl: './ajout-publication.component.html',
  styleUrl: './ajout-publication.component.scss'
})
export class AjoutPublicationComponent {
  titre = '';
  contenu = '';
  errorMessage = '';

  constructor(
    private authService: AuthService,
    public dialogRef: MatDialogRef<AjoutPublicationComponent>
  ) {}

  submitPublication(): void {
    const data = { titre: this.titre, contenu: this.contenu };
    this.authService.addPublication(data).subscribe({
      next: () => this.dialogRef.close(true),
      error: () => (this.errorMessage = 'Erreur lors de l’ajout.')
    });
  }

  closeDialog(): void {
    this.dialogRef.close(false);
  }

}
