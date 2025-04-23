import { CommonModule } from '@angular/common';
import { Component, Inject, OnInit } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-detail-publication',
  standalone: true,
  imports: [ CommonModule,
      
      MatDialogModule,
      
      MatInputModule,
      MatButtonModule],
  templateUrl: './detail-publication.component.html',
  styleUrl: './detail-publication.component.scss'
})
export class DetailPublicationComponent implements OnInit {
  publication: any;
  error = '';

  constructor(
    @Inject(MAT_DIALOG_DATA) public data: { id: number },
    private authService: AuthService,
    public dialogRef: MatDialogRef<DetailPublicationComponent>
  ) {}

  ngOnInit(): void {
    this.authService.getPublicationById(this.data.id).subscribe({
      next: (res) => this.publication = res,
      error: () => this.error = "Erreur lors du chargement."
    });
  }

  close(): void {
    this.dialogRef.close();
  }
}
