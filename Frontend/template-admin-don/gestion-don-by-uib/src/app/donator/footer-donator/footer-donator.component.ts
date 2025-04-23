import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-footer-donator',
  standalone: true,
  imports: [],
  templateUrl: './footer-donator.component.html',
  styleUrl: './footer-donator.component.scss'
})
export class FooterDonatorComponent implements OnInit {
  test : Date = new Date();
  
  constructor() { }

  ngOnInit() {
  }

}
