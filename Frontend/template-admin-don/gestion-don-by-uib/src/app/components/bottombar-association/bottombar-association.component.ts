import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-bottombar-association',
  standalone: true,
  imports: [],
  templateUrl: './bottombar-association.component.html',
  styleUrl: './bottombar-association.component.scss'
})
export class BottombarAssociationComponent implements OnInit {
  test : Date = new Date();
  
  constructor() { }

  ngOnInit() {
  }

}
