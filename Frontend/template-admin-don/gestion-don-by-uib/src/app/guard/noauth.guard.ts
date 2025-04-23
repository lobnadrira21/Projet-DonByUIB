import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';


@Injectable({
  providedIn: 'root'
})
export class NoAuthGuard implements CanActivate {
  constructor(private authService: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    const token = this.authService.getToken();
    const currentUrl = state.url;
    console.log("🔍 NoAuthGuard - Checking route:", currentUrl);
  
    // Autoriser accès à la page reset-password même si connecté
    if (currentUrl.startsWith('/reset-password')) {
      console.log("🔓 Accès autorisé à reset-password même avec token.");
      return true;
    }
  
    // ✅ Autoriser les donateurs à accéder à /client même connectés
    const userRole = localStorage.getItem('role');
    if (token && currentUrl === '/client' && (userRole === 'donator' || userRole === 'association')) {
      console.log("✅ Access to /client allowed for role:", userRole);
      return true;
    }
    
  
    // Si pas connecté
    if (!token) {
      console.log("✅ User is NOT logged in, allowing access.");
      return true;
    }
  
    // Sinon redirection selon le rôle
    console.log("🚨 User IS logged in, role:", userRole);
    if (userRole === 'admin') {
      this.router.navigate(['/dashboard']);
    } else if (userRole === 'association') {
      this.router.navigate(['/dashboard-association']);
    } else if (userRole === 'donator') {
      this.router.navigate(['/dashboard-donator']);
    } else {
      this.router.navigate(['/login']);
    }
  
    return false;
  }
  
  
}