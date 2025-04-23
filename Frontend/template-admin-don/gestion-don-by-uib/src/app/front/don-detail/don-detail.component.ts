import { CommonModule } from '@angular/common';
import { Component, HostListener, OnInit } from '@angular/core';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { HeaderFrontComponent } from '../header-front/header-front.component';

@Component({
  selector: 'app-don-detail',
  standalone: true,
  imports: [CommonModule, HeaderFrontComponent, RouterModule],
  templateUrl: './don-detail.component.html',
  styleUrl: './don-detail.component.scss'
})
export class DonDetailComponent implements OnInit {
  donId: number = 0;
  don: any;
  isLoggedIn: boolean = false;
  username: string | null = null;

  constructor(private route: ActivatedRoute, private authService: AuthService, private router: Router) {}



  ngOnInit(): void {
    this.donId = +this.route.snapshot.paramMap.get('id')!;
    this.authService.getDonById(this.donId).subscribe({
      next: data => this.don = data,
      error: err => console.error(err)
    });

  }

  getPourcentage(montant: number, objectif: number): number {
    return objectif > 0 ? Math.round((montant / objectif) * 100) : 0;
  }
  

}
