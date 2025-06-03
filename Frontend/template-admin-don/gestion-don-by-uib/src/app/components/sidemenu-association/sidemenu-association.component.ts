import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router'; // ✅ Import RouterModule

declare const $: any;

declare interface RouteInfo {
    path: string;
    title: string;
    icon: string;
    class: string;
}
export const ROUTES: RouteInfo[] = [
  { path: '/dashboard-association', title: 'Dashboard',  icon: 'dashboard', class: '' }, // ✅ Fixed
  { path: '/dashboard-association/user-profile', title: 'User Profile',  icon:'person', class: '' }, // ✅ Fixed
  { path: '/dashboard-association/table-list', title: 'Table List',  icon:'content_paste', class: '' }, // ✅ Fixed
  { path: '/dashboard-association/payment-recu', title: 'payment',  icon:'payments', class: '' } // ✅ Fixed
];

@Component({
  selector: 'app-sidemenu-association',
  standalone: true,
  imports: [RouterModule], // ✅ Import RouterModule to use 'routerLink'
  templateUrl: './sidemenu-association.component.html',
  styleUrls: ['./sidemenu-association.component.scss']
})
export class SidemenuAssociationComponent implements OnInit {
  menuItems: any[];

  constructor() { }

  ngOnInit() {
    this.menuItems = ROUTES.filter(menuItem => menuItem);
  }
  isMobileMenu() {
      return $(window).width() <= 991;
  }
}
