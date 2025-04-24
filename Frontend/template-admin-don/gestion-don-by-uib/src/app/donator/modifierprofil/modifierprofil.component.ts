import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { Router } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-modifierprofil',
  standalone: true,
  imports: [ MatFormFieldModule,  // ✅ Import Material Form Field
      MatInputModule,      // ✅ Import Material Input
      MatButtonModule,
      ReactiveFormsModule,],
  templateUrl: './modifierprofil.component.html',
  styleUrl: './modifierprofil.component.scss'
})
export class ModifierprofilComponent implements OnInit {

  profileForm!: FormGroup;
  message: string ='';
   constructor(private authService: AuthService, private fb: FormBuilder,private router: Router) {}
  ngOnInit(): void {
     this.profileForm = this.fb.group({
         nom_complet: ['', Validators.required],
         email: ['', [Validators.required, Validators.email]],
         
         telephone: ['', Validators.required],
        
         old_password: [''],
         new_password: [''],
       
       });
  }

  updateProfileDonator() {
    if (this.profileForm.invalid) return;

    const formData = new FormData();
  
    // Ajouter les champs du formulaire dans FormData
    Object.keys(this.profileForm.controls).forEach(key => {
      const value = this.profileForm.get(key)?.value;
      formData.append(key, value);
    });
  
   
  
    const token = this.authService.getToken();
    if (!token) {
      console.error("No token found. User is not authenticated.");
      return;
    }
  
    this.authService.modifyProfileDonator(formData).subscribe(
      (response) => {
        console.log("Profile updated successfully:", response);
        this.message = "Profil mis à jour avec succès !";
        setTimeout(() => {
          this.router.navigate(['/dashboard-donator/welcome-donator']);
        }, 1000);
      },

      (error) => {
        console.error("Error updating profile:", error);
        this.message = error.error?.error || "Erreur lors de la mise à jour du profil.";
      }
    );
  }

}
