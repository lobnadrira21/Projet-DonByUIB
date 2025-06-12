import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { TypeAssociation } from 'app/models/type-association.model';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-modifier-compte-association',
  standalone: true,
  imports: [CommonModule,
        FormsModule,
        MatDialogModule,
        MatFormFieldModule,
        MatInputModule,
        MatButtonModule,
        RouterModule,
       MatSelectModule ],
  templateUrl: './modifier-compte-association.component.html',
  styleUrl: './modifier-compte-association.component.scss'
})
export class ModifierCompteAssociationComponent  implements OnInit   {
  typesAssociation: string[] = Object.values(TypeAssociation);
  id!: number;
  association = {
    nom_complet: '',
    email: '',
    description_association: '',
    telephone: 0,
    adresse: '',
    type_association:''

  };
  ngOnInit(): void {
    this.id = Number(this.route.snapshot.paramMap.get('id'));
    this.authService.getAssociationById(this.id).subscribe({
      next: (res) => {
        this.association.nom_complet = res.nom_complet;
        this.association.email= res.email;
        this.association.description_association=res.description_association;
        this.association.telephone=res.telephone;
        this.association.adresse=res.adresse;
        this.association.type_association=res.type_association;
      },
      error: (err) => console.error(err)
    });
  }

  onUpdate(): void {
    const formData = new FormData();
  
    formData.append('nom_complet', this.association.nom_complet);
    formData.append('email', this.association.email);
    formData.append('description_association', this.association.description_association);
    formData.append('telephone', this.association.telephone.toString());
    formData.append('adresse', this.association.adresse);
    formData.append('type_association', this.association.type_association);
  
    this.authService.modifyAccount(this.id, formData).subscribe({
      next: () => {
        alert('✅ Association mise à jour avec succès');
        this.router.navigate(['/dashboard/gestion-associations']);
      },
      error: (err) => console.error(err)
    });
  }
  


   constructor(
      private route: ActivatedRoute,
      private authService: AuthService,
      private router: Router
    ) {}

}
