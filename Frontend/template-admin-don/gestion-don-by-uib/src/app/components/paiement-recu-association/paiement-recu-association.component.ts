import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { MatDialog } from '@angular/material/dialog';
import { OcrModalFileComponent } from '../../modals/ocr-modal-file/ocr-modal-file.component';

@Component({
  selector: 'app-paiement-recu-association',
  standalone: true,
  imports: [CommonModule,RouterModule],
  templateUrl: './paiement-recu-association.component.html',
  styleUrl: './paiement-recu-association.component.scss'
})
export class PaiementRecuAssociationComponent implements OnInit {
  paiements: any[] = [];

  constructor(private authService: AuthService, private http: HttpClient, private dialog: MatDialog) {}

  ngOnInit(): void {
  this.authService.getPaiementsAssociation().subscribe({
    next: (data) => {
      this.paiements = data;
    },
    error: (err) => {
      console.error("Erreur lors du chargement des paiements :", err);
    }
  });
}



extraireTexteOCR(participationId: number) {
  this.http.get<any>(`http://127.0.0.1:5000/ocr-recu/${participationId}`).subscribe({
  next: res => {
    const structured = res.structured_data;
    structured["id_participation"] = participationId; 
    this.dialog.open(OcrModalFileComponent, {
      data: structured,
      width: '450px'
    });
  },
  error: err => {
    console.error("Erreur OCR :", err);
    alert("Erreur lors de l'OCR.");
  }
});

}


}

