import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-body-donator',
  standalone: true,
  imports: [RouterModule,CommonModule, ReactiveFormsModule],
  templateUrl: './body-donator.component.html',
  styleUrl: './body-donator.component.scss'
})
export class BodyDonatorComponent implements OnInit   {

  profileForm!: FormGroup;
     constructor(private authService: AuthService, private fb: FormBuilder) {}
    ngOnInit(): void {
      this.profileForm = this.fb.group({
        nom_complet: [''],
        email: [''],
    
        telephone: [''],
      
      });
    
      this.loadProfileDonator(); 
    }
    
    loadProfileDonator() {
      this.authService.getProfileDonator().subscribe(
        (data) => {
          this.profileForm.patchValue(data);
        },
        (error) => {
          console.error("Erreur lors du chargement du profil :", error);
        }
      );
    }

}
