import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { MatIconModule } from '@angular/material/icon';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-association-detail',
  standalone: true,
  imports: [CommonModule,MatIconModule],
  templateUrl: './association-detail.component.html',
  styleUrl: './association-detail.component.scss'
})
export class AssociationDetailComponent  implements OnInit {
  associationId!: number;
  association: any = null;

  constructor(private route: ActivatedRoute, private http: HttpClient) {}

  ngOnInit(): void {
    this.associationId = Number(this.route.snapshot.paramMap.get('id'));
    this.loadAssociation();
  }

  loadAssociation() {
    this.http.get(`http://localhost:5000/public-association/${this.associationId}`).subscribe({
      next: (res: any) => {
        this.association = res;
      },
      error: (err) => {
        console.error('Erreur lors du chargement :', err);
      }
    });
  }

}
