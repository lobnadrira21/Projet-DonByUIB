import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://127.0.0.1:5000'; // Flask Backend URL

  constructor(private http: HttpClient, private router: Router) {}

  /** Login with email and password */
  login(email: string, password: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/login`, { email, password });
  }

  saveToken(token: string, role: string, username: string): void {
    localStorage.setItem('token', token); // 👈 this must match getToken()
    localStorage.setItem('role', role);
    localStorage.setItem('username', username);
  }
  
  
  getUsername(): string | null {
    return localStorage.getItem('username');
  }
  
  getUser(): { username: string | null, role: string | null } {
    return {
      username: localStorage.getItem('username'),
      role: localStorage.getItem('role')
    };
  }
  

  /** Retrieve token from local storage */
  getToken(): string | null {
    return localStorage.getItem('token'); // 🔄 FIXED: use 'token' not 'access_token'
  }
  

  logout(): void {
    const token = this.getToken(); // Get the JWT token

    if (!token) {
      console.error('No token found, logging out locally');
      this.clearSession();
      return;
    }

    const headers = new HttpHeaders({
      Authorization: `Bearer ${token}`
    });

    this.http.post(`${this.apiUrl}/logout`, {}, { headers }).subscribe(
      () => {
        console.log('Logged out successfully');
        this.clearSession();
      },
      error => {
        console.error('Logout failed, clearing session anyway', error);
        this.clearSession();
      }
    );
  }

  /** Clear user session (localStorage and redirect) */
  private clearSession(): void {
    localStorage.removeItem('token'); // ✅ Remove token
    localStorage.removeItem('role'); // ✅ Remove role (Important!)
    this.router.navigate(['/login']); // ✅ Redirect to login page
  }



  /** Register a new user */
register(userData: any): Observable<any> {
  return this.http.post<any>(`${this.apiUrl}/register`, userData);
}

getAssociations(): Observable<any[]> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  return this.http.get<any[]>(`${this.apiUrl}/associations`, { headers });
}

 /** Modify association profile */
 modifyProfile(data: FormData): Observable<any> {
  const headers = {
    Authorization: `Bearer ${this.getToken()}`,
  };

  return this.http.put(`${this.apiUrl}/modify-profile-association`, data, { headers });
}

getProfile(): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    'Authorization': `Bearer ${token}`
  });

  return this.http.get<any>(`${this.apiUrl}/get-profile-association`, { headers });
}

getDons(): Observable<any[]> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });
  return this.http.get<any[]>(`${this.apiUrl}/dons`, { headers });
}


getAllDonsPublic(): Observable<any[]> {
  return this.http.get<any[]>('http://127.0.0.1:5000/public-dons');
}

getPublications(): Observable<any[]> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  return this.http.get<any[]>(`${this.apiUrl}/publications`, { headers });
}

addPublication(data: any): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json'
  });

  return this.http.post(`${this.apiUrl}/add-publications`, data, { headers });
}

getPublicationById(id: number): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  return this.http.get(`${this.apiUrl}/publication/${id}`, { headers });
}
updatePublication(id: number, data: any): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  });

  return this.http.put(`${this.apiUrl}/update-publication/${id}`, data, { headers });
}
deletePublication(id: number): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  return this.http.delete(`${this.apiUrl}/delete-publication/${id}`, { headers });
}

addComment(publicationId: number, contenu: string) {
  const token = this.getToken(); // Assure-toi que cette méthode existe
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  const body = { contenu };

  return this.http.post(`${this.apiUrl}/add-comment/${publicationId}`, body, { headers });
}

getNotifications(): Observable<any[]> {
  const token = this.getToken();
  const headers = new HttpHeaders({ Authorization: `Bearer ${token}` });
  return this.http.get<any[]>(`${this.apiUrl}/notifications`, { headers });
}

likePublication(id: number) {
  const token = this.getToken();
  const headers = new HttpHeaders({
    Authorization: `Bearer ${token}`
  });

  return this.http.post(`${this.apiUrl}/like-publication/${id}`, {}, { headers });
}

getDonById(id: number): Observable<any> {
  return this.http.get(`${this.apiUrl}/don/${id}`);
}

// auth.service.ts
participatedons(id_don: number, data: any) {
  const token = this.getToken(); // Vérifie bien que c'est le token du DONATEUR
  return this.http.post(
    `http://127.0.0.1:5000/participate/${id_don}`,
    data,
    {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      }
    }
  );
}


getDonParticipants(): Observable<any[]> {
  return this.http.get<any[]>(`${this.apiUrl}/don-participants`);
}

getProfileDonator(): Observable<any> {
  const token = this.getToken();
  const headers = new HttpHeaders({
    'Authorization': `Bearer ${token}`
  });

  return this.http.get<any>(`${this.apiUrl}/get-profile-donator`, { headers });
}

modifyProfileDonator(data: FormData): Observable<any> {
  const headers = {
    Authorization: `Bearer ${this.getToken()}`,
  };

  return this.http.put(`${this.apiUrl}/modify-profile-donateur`, data, { headers });
}

}
