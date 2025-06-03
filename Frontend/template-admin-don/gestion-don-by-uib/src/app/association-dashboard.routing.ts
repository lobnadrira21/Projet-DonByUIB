import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { EspaceAssociationComponent } from './components/espace-association/espace-association.component';
import { UserProfileComponent } from './user-profile/user-profile.component';
import { TableListComponent } from './table-list/table-list.component';
import { BodyAssociationComponent } from './components/body-association/body-association.component';
import { ListPublicationComponent } from './components/list-publication/list-publication.component';
import { ModifierPublicationComponent } from './components/modifier-publication/modifier-publication.component';
import { ModifierDonComponent } from './components/modifier-don/modifier-don.component';
import { PaiementRecuAssociationComponent } from './components/paiement-recu-association/paiement-recu-association.component';

const routes: Routes = [
  {
    path: 'dashboard-association',
    component: EspaceAssociationComponent,
    children: [
      { path: '', redirectTo: 'accueil-association', pathMatch: 'full' },
      { path: 'accueil-association', component: BodyAssociationComponent },
      
      { 
        path: 'user-profile', 
        component: UserProfileComponent  // ✅ Use "component", not "loadComponent"
      },
      {
        path: 'table-list',
        component: TableListComponent
      },
      {path: 'table-publication', component: ListPublicationComponent},
       { path: 'modifier-publication/:id', component: ModifierPublicationComponent },
       {path: 'modifier-don/:id',component:ModifierDonComponent},
       {path: 'payment-recu',component:PaiementRecuAssociationComponent}
    ]
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AssociationDashboardRoutingModule { }
