import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-modifier-publication',
  standalone: true,
  imports: [CommonModule,
      FormsModule,
      MatDialogModule,
      MatFormFieldModule,
      MatInputModule,
      MatButtonModule,
      RouterModule],
  templateUrl: './modifier-publication.component.html',
  styleUrl: './modifier-publication.component.scss'
})
export class ModifierPublicationComponent  implements OnInit {
  id!: number;
  publication = {
    titre: '',
    contenu: ''
  };

  constructor(
    private route: ActivatedRoute,
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.id = Number(this.route.snapshot.paramMap.get('id'));
    this.authService.getPublicationById(this.id).subscribe({
      next: (res) => {
        this.publication.titre = res.titre;
        this.publication.contenu = res.contenu;
      },
      error: (err) => console.error(err)
    });
  }

  onUpdate(): void {
    this.authService.updatePublication(this.id, this.publication).subscribe({
      next: () => {
        alert('✅ Publication mise à jour avec succès');
        this.router.navigate(['/dashboard-association/table-publication']);
      },
      error: (err) => console.error(err)
    });
  }
}
