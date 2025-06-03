import { NgModule } from '@angular/core';
import { CommonModule, } from '@angular/common';
import { BrowserModule  } from '@angular/platform-browser';
import { Routes, RouterModule } from '@angular/router';

import { AdminLayoutComponent } from './layouts/admin-layout/admin-layout.component';
import { EspaceAssociationComponent } from './components/espace-association/espace-association.component';
import { PageclientComponent } from './front/pageclient/pageclient.component';
import { UserProfileComponent } from './user-profile/user-profile.component';
import { AuthGuard } from './guard/auth.guard';
import { RegisterComponent } from './authentification/register/register.component';
import { LoginComponent } from './authentification/login/login.component';
import { RoleGuard } from './guard/role.guard';
import { NoAuthGuard } from './guard/noauth.guard';
import { EspaceDonatorComponent } from './donator/espace-donator/espace-donator.component';
import { GestionUsersComponent } from './admin/gestion-users/gestion-users.component';
import { AssociationDashboardRoutingModule } from './association-dashboard.routing';
import { TableListComponent } from './table-list/table-list.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { AdminLayoutRoutingModule } from './layouts/admin-layout/admin-layout.routing';
import { AjoutAssociationComponent } from './admin/ajout-association/ajout-association.component';
import { BodyAssociationComponent } from './components/body-association/body-association.component';
import { ResetPasswordComponent } from './authentification/reset-password/reset-password.component';
import { ChangePasswordComponent } from './authentification/change-password/change-password.component';
import { ListPublicationComponent } from './components/list-publication/list-publication.component';
import { AjoutPublicationComponent } from './components/ajout-publication/ajout-publication.component';
import { ModifierPublicationComponent } from './components/modifier-publication/modifier-publication.component';
import { DonDetailComponent } from './front/don-detail/don-detail.component';
import { ParticiperDonComponent } from './front/participer-don/participer-don.component';
import { SuccessComponent } from './front/success/success.component';
import { FailComponent } from './front/fail/fail.component';
import { ModifierprofilComponent } from './donator/modifierprofil/modifierprofil.component';
import { BodyDonatorComponent } from './donator/body-donator/body-donator.component';
import { ValiderRefuserDonComponent } from './admin/valider-refuser-don/valider-refuser-don.component';
import { ModifierDonComponent } from './components/modifier-don/modifier-don.component';
import { ModifierCompteAssociationComponent } from './admin/modifier-compte-association/modifier-compte-association.component';
import { ValiderRefuserPublicationComponent } from './admin/valider-refuser-publication/valider-refuser-publication.component';
import { MesPaiementsComponent } from './donator/mes-paiements/mes-paiements.component';
import { AssociationDetailComponent } from './front/association-detail/association-detail.component';
import { HistoriqueDonatorComponent } from './donator/historique-donator/historique-donator.component';
import { PaiementRecuAssociationComponent } from './components/paiement-recu-association/paiement-recu-association.component';

export const routes: Routes = [
  { path: '', redirectTo: 'client', pathMatch: 'full' },



  // 🚀 **Client Page (ONLY for logged-out users)**
  { path: 'client', component: PageclientComponent, canActivate: [NoAuthGuard] }, // ✅ Apply NoAuthGuard

  // 🚀 **Admin Dashboard (Protected)**
  {
    path: 'dashboard',
    component: AdminLayoutComponent,
    canActivate: [AuthGuard, RoleGuard], // ✅ Apply guards
    data: { role: 'admin' },
    children: [  
      { path: '', redirectTo: 'stat', pathMatch: 'full' },  // ✅ Default route when visiting /dashboard
      { path: 'stat', component: DashboardComponent },      // ✅ Show statistics on /dashboard
      { path: 'gestion-associations', component: GestionUsersComponent },
      { path: 'admin-valider-don', component: ValiderRefuserDonComponent },
      { path: 'admin-valider-publication', component: ValiderRefuserPublicationComponent },
      { path: 'modifier-compte-association/:id', component: ModifierCompteAssociationComponent },
      
    ]
  },

  // 🚀 **Association Dashboard (Protected)**
  {
    path: 'dashboard-association',
    component: EspaceAssociationComponent,
    canActivate: [AuthGuard, RoleGuard], // ✅ Apply guards
    data: { role: 'association' }
    ,
    children: [  // ✅ Add child routes here!
      { path: '', redirectTo: 'accueil-association', pathMatch: 'full' },
{ path: 'accueil-association', component: BodyAssociationComponent },

      { path: 'user-profile', component: UserProfileComponent },
      { path: 'table-list', component: TableListComponent },
      {path: 'table-publication', component: ListPublicationComponent},
      { path: 'modifier-publication/:id', component: ModifierPublicationComponent },
      {path: 'modifier-don/:id',component:ModifierDonComponent},
      {path: 'payment-recu', component:PaiementRecuAssociationComponent}
    ]
  },


  
  {
    path: 'dashboard-donator',
    component: EspaceDonatorComponent,
    canActivate: [AuthGuard, RoleGuard], // ✅ Apply guards
    data: { role: 'donator' },
    children: [
      { path: '', redirectTo: 'welcome-donator', pathMatch: 'full' },
      {path:'welcome-donator',component:BodyDonatorComponent},
      {path:'modifier-profil', component: ModifierprofilComponent},
      {path:'mes-paiements', component: MesPaiementsComponent,canActivate: [AuthGuard]},
      {path: 'historique', component: HistoriqueDonatorComponent }
    ]
  },

  // independant routes 
  { path: 'login', component: LoginComponent } ,
  { path: 'register', component: RegisterComponent } ,
  { path: 'ajouter-association', component: AjoutAssociationComponent },
  {path:'ajouter-publication', component: AjoutPublicationComponent},


 

  {
    path: 'request-password', component:ResetPasswordComponent
  },
  {
    path: 'reset-password/:token', component:ChangePasswordComponent
  },
  {
    path: 'don/:id',
    component: DonDetailComponent
  },
  {
  path: 'participate/:id',
  component: ParticiperDonComponent
  },
  {
    path: 'success',
    component: SuccessComponent
    },
    {
      path: 'fail',
      component: FailComponent
      },

     {
      path: 'detail-association/:id',
      component: AssociationDetailComponent
      },



  
  
];


@NgModule({
  imports: [
    CommonModule,
    BrowserModule,
    RouterModule.forRoot(routes, { useHash: true }),
    AssociationDashboardRoutingModule,
    AdminLayoutRoutingModule
  ],
  exports: [RouterModule]
})
export class AppRoutingModule { }