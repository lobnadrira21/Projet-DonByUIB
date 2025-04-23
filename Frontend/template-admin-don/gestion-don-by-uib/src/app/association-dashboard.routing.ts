import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { EspaceAssociationComponent } from './components/espace-association/espace-association.component';
import { UserProfileComponent } from './user-profile/user-profile.component';
import { TableListComponent } from './table-list/table-list.component';
import { BodyAssociationComponent } from './components/body-association/body-association.component';
import { ListPublicationComponent } from './components/list-publication/list-publication.component';
import { ModifierPublicationComponent } from './components/modifier-publication/modifier-publication.component';

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
    ]
  }
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AssociationDashboardRoutingModule { }
