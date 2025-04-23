import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { AuthService } from 'app/services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class RoleGuard implements CanActivate {
  constructor(private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot): boolean {
    console.log("🔍 RoleGuard - Checking role...");
    const role = localStorage.getItem('role');
    console.log("🔍 Stored Role:", role);

    if (!role) {
      console.log("🚨 No role found! Redirecting to login...");
      this.router.navigate(['/login']);
      return false;
    }

    const expectedRole = route.data['role'];
    if (expectedRole && role !== expectedRole) {
      console.log(`🚨 Role mismatch! Expected: ${expectedRole}, Found: ${role}`);
      this.router.navigate(['/login']);
      return false;
    }

    console.log("✅ Role is valid, access granted.");
    return true;
  }
}