import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { AppRoutingModule } from './app.routing';

import { AppComponent } from './app.component';
import { AdminLayoutComponent } from './layouts/admin-layout/admin-layout.component';
import { EspaceAssociationComponent } from './components/espace-association/espace-association.component';
import { TopbarAssociationComponent } from './components/topbar-association/topbar-association.component';
import { SidemenuAssociationComponent } from './components/sidemenu-association/sidemenu-association.component';
import { BottombarAssociationComponent } from './components/bottombar-association/bottombar-association.component';
import { CommonModule } from '@angular/common';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { AjoutAssociationComponent } from './admin/ajout-association/ajout-association.component';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthInterceptor } from './interceptors/auth.interceptor';

@NgModule({
  imports: [
    BrowserAnimationsModule,
    FormsModule,
    ReactiveFormsModule,
    HttpClientModule,
    MatFormFieldModule, // ✅ Needed for <mat-form-field>
    MatInputModule, // ✅ Needed for matInput
    MatDialogModule, // ✅ Needed for the modal/dialog
    MatButtonModule, // ✅ Needed for <button mat-button>
    RouterModule,
    AppRoutingModule,
    AdminLayoutComponent,
    EspaceAssociationComponent,
    TopbarAssociationComponent,
    SidemenuAssociationComponent,
    BottombarAssociationComponent,
    CommonModule, 
    MatFormFieldModule, // ✅ Required for mat-form-field
    MatInputModule,
   
  ],
  declarations: [
    AppComponent,


  ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
