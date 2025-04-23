import { Component, OnInit } from '@angular/core';
import { RouterModule } from '@angular/router';
declare const $: any;

declare interface RouteInfo {
    path: string;
    title: string;
    icon: string;
    class: string;
}
export const ROUTES: RouteInfo[] = [
  { path: '/dashboard-donator', title: 'Dashboard',  icon: 'dashboard', class: '' }, // ✅ Fixed
  
];
@Component({
  selector: 'app-sidebar-donator',
  standalone: true,
  imports: [RouterModule],
  templateUrl: './sidebar-donator.component.html',
  styleUrl: './sidebar-donator.component.scss'
})
export class SidebarDonatorComponent implements OnInit {
  menuItems: any[];

  constructor() { }

  ngOnInit() {
    this.menuItems = ROUTES.filter(menuItem => menuItem);
  }
  isMobileMenu() {
      return $(window).width() <= 991;
  }
}