import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { Component, ElementRef, OnInit, ViewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatFormField, MatFormFieldModule, MatLabel } from '@angular/material/form-field';
import { MatIcon, MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-body-front',
  standalone: true,
  imports: [CommonModule,HttpClientModule,FormsModule,MatIconModule,MatFormFieldModule,MatInputModule, RouterModule],
  templateUrl: './body-front.component.html',
  styleUrl: './body-front.component.scss'
})
export class BodyFrontComponent implements OnInit {
  dons: any[] = [];
  searchTerm: string = '';
  allDons: any[] = [];
  publications: any[] = [];
  selectedPublication: any = null;
  newComment: string = '';
  donParticipants: { [key: number]: number } = {};
 


  constructor(private authService: AuthService) {}

  
  scrollToCatalog() {
    document.getElementById('catalog')?.scrollIntoView({ behavior: 'smooth' });
  }
  
  scrollToPublications() {
    document.getElementById('publication')?.scrollIntoView({ behavior: 'smooth' });
  }
  
@ViewChild('carousel', { static: false }) carousel!: ElementRef;

scrollLeft() {
  this.carousel.nativeElement.scrollBy({ left: -350, behavior: 'smooth' });
}

scrollRight() {
  this.carousel.nativeElement.scrollBy({ left: 350, behavior: 'smooth' });
}

currentSlide = 0;

get totalSlides(): number {
  return Math.ceil(this.publications.length / 4);
}

prevSlide() {
  if (this.currentSlide > 0) {
    this.currentSlide--;
  }
}

nextSlide() {
  if (this.currentSlide < this.totalSlides - 1) {
    this.currentSlide++;
  }
}


  animateCard(event: Event) {
    const card = event.currentTarget as HTMLElement;
    card.style.transform = 'translateY(-5px)';
    setTimeout(() => {
      card.style.transform = 'translateY(0)';
    }, 300);
  }

  ngOnInit(): void {
    this.refreshDonsAndParticipants();
    this.authService.getPublications().subscribe({
      next: (data) => {
        this.publications = data;
      },
      error: (err) => {
        console.error('Erreur lors du chargement des publications :', err);
      }
    });
   
  }

  refreshDonsAndParticipants() {
    this.authService.getAllDonsPublic().subscribe({
      next: (data) => {
        this.allDons = data;
        this.dons = data;
      },
      error: (err) => {
        console.error('Erreur lors du chargement des dons publics :', err);
      }
    });
    this.authService.getDonParticipants().subscribe({
      next: (res) => {
        res.forEach(p => {
          this.donParticipants[p.id_don] = p.nb_participants;
        });
      },
      error: (err) => {
        console.error('Erreur lors du chargement des participants :', err);
      }
    });
  

    
  }

  onSearch() {
    const search = this.searchTerm.toLowerCase().trim();
    this.dons = this.allDons.filter(don =>
      don.titre.toLowerCase().includes(search) ||
      don.description?.toLowerCase().includes(search)
    );
  }
  
  

  
  selectPublication(pub: any) {
    this.selectedPublication = pub;
  }

  addComment() {
    const contenu = this.newComment.trim();
    const publicationId = this.selectedPublication?.id_publication;
  
    if (contenu && publicationId) {
      this.authService.addComment(publicationId, contenu).subscribe({
        next: (res) => {
          // Ajouter le commentaire à l'affichage après succès
          this.selectedPublication.commentaires.push({
            nom: this.authService.getUsername() || 'Moi',
            contenu: contenu
          });
          this.newComment = '';
          console.log('✅ Commentaire ajouté :', res);
        },
        error: (err) => {
          console.error('❌ Erreur lors de l’ajout du commentaire :', err);
          alert(err.error?.error || 'Erreur inconnue');
        }
      });
    }
  }
  

  likeSelectedPublication() {
    if (!this.selectedPublication) return;
  
    this.authService.likePublication(this.selectedPublication.id_publication).subscribe({
      next: (res: any) => {
        this.selectedPublication.nb_likes = res.nb_likes;
      },
      error: (err) => {
        console.error("Erreur lors du like :", err);
        alert(err.error?.error || "Erreur lors du like");
      }
    });
  }





  
  

}