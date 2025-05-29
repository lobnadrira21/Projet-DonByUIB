import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-historique-donator',
  standalone: true,
  imports: [CommonModule,RouterModule],
  templateUrl: './historique-donator.component.html',
  styleUrl: './historique-donator.component.scss'
})
export class HistoriqueDonatorComponent implements OnInit {
  historique: any[] = [];
constructor(private authService: AuthService){}
ngOnInit() {
  this.authService.getHistorique().subscribe(data => {
    this.historique = data;
  });
}


}
