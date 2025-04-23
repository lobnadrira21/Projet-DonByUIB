import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-body-association',
  standalone: true,
  imports: [RouterModule,CommonModule, ReactiveFormsModule],
  templateUrl: './body-association.component.html',
  styleUrl: './body-association.component.scss'
})
export class BodyAssociationComponent implements OnInit {
profileForm!: FormGroup;
   constructor(private authService: AuthService, private fb: FormBuilder) {}
  ngOnInit(): void {
    this.profileForm = this.fb.group({
      nom_complet: [''],
      email: [''],
      description_association: [''],
      telephone: [''],
      adresse: [''],
      type_association: [''],
      photo: ['']
    });
  
    this.loadProfile(); // Appelle le backend
  }
  
  loadProfile() {
    this.authService.getProfile().subscribe(
      (data) => {
        this.profileForm.patchValue(data);
      },
      (error) => {
        console.error("Erreur lors du chargement du profil :", error);
      }
    );
  }
  

}
