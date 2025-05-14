import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-modifier-don',
  standalone: true,
  imports: [ CommonModule,
    ReactiveFormsModule,
    FormsModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule],
  templateUrl: './modifier-don.component.html',
  styleUrl: './modifier-don.component.scss'
})
export class ModifierDonComponent implements OnInit {
  donForm!: FormGroup;
  id_don!: number;
  imagePreview: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.id_don = +this.route.snapshot.paramMap.get('id')!;
    this.initForm();
    this.loadDon();
  }

  initForm() {
    this.donForm = this.fb.group({
      titre: ['', Validators.required],
      description: [''],
      objectif: ['', Validators.required],
      date_fin_collecte: ['', Validators.required],
      photo_file: [null]
    });
  }

  loadDon() {
    this.authService.getDonById(this.id_don).subscribe({
      next: (don) => {
        this.donForm.patchValue({
          titre: don.titre,
          description: don.description,
          objectif: don.objectif,
          date_fin_collecte: don.date_fin_collecte
        });
        if (don.photo_don) {
          this.imagePreview = 'http://127.0.0.1:5000' + don.photo_don;
        }
      },
      error: (err) => console.error('Erreur chargement don:', err)
    });
  }

  onFileSelected(event: any) {
    const file = event.target.files[0];
    if (file) {
      this.donForm.patchValue({ photo_file: file });

      const reader = new FileReader();
      reader.onload = () => (this.imagePreview = reader.result as string);
      reader.readAsDataURL(file);
    }
  }

  onSubmit() {
    const formData = new FormData();
    for (const key in this.donForm.value) {
      if (this.donForm.value[key] !== null) {
        formData.append(key, this.donForm.value[key]);
      }
    }

    this.authService.updateDon(this.id_don, formData).subscribe({
      next: () => {
        alert('✅ Don modifié avec succès');
        this.router.navigate(['/dashboard-association/table-list']);
      },
      error: (err) => {
        console.error('Erreur lors de la modification', err);
        alert('❌ Erreur lors de la modification');
      }
    });
  }

}
