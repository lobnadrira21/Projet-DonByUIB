import { HttpClient } from '@angular/common/http';
import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-ocr-modal-file',
  standalone: true,
  imports: [],
  templateUrl: './ocr-modal-file.component.html',
  styleUrl: './ocr-modal-file.component.scss'
})
export class OcrModalFileComponent {
   constructor( private authService: AuthService,
    private http: HttpClient,
    public dialogRef: MatDialogRef<OcrModalFileComponent>,
    @Inject(MAT_DIALOG_DATA) public data: any
  ) {}

  close() {
    this.dialogRef.close();
  }

  downloadRecu(participationId: number) {
  this.authService.getRecuPaiement(participationId).subscribe(blob => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recu_don_${participationId}.pdf`;
    a.click();
    window.URL.revokeObjectURL(url);
  });
}
}


