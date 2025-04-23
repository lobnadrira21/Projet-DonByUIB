import { Component } from '@angular/core';
import { HeaderFrontComponent } from '../header-front/header-front.component';
import { BodyFrontComponent } from '../body-front/body-front.component';
import { FooterFrontComponent } from '../footer-front/footer-front.component';

@Component({
  selector: 'app-pageclient',
  standalone: true,
  imports: [HeaderFrontComponent,BodyFrontComponent,FooterFrontComponent],
  templateUrl: './pageclient.component.html',
  styleUrl: './pageclient.component.scss'
})
export class PageclientComponent {

}
