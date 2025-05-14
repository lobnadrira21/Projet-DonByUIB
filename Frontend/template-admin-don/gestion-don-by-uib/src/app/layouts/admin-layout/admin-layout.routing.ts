import { NgModule } from '@angular/core';

import { RouterModule, Routes } from '@angular/router';
import { AdminLayoutComponent } from './admin-layout.component';

import { DashboardComponent } from '../../dashboard/dashboard.component';
import { UserProfileComponent } from '../../user-profile/user-profile.component';
import { TableListComponent } from '../../table-list/table-list.component';
import { TypographyComponent } from '../../typography/typography.component';
import { IconsComponent } from '../../icons/icons.component';
import { MapsComponent } from '../../maps/maps.component';
import { NotificationsComponent } from '../../notifications/notifications.component';
import { UpgradeComponent } from '../../upgrade/upgrade.component';
import { GestionUsersComponent } from 'app/admin/gestion-users/gestion-users.component';
import { AjoutAssociationComponent } from 'app/admin/ajout-association/ajout-association.component';
import { ValiderRefuserDonComponent } from 'app/admin/valider-refuser-don/valider-refuser-don.component';
const routes: Routes = [
    {
      path: 'dashboard',
      component: AdminLayoutComponent,
      children: [
        { path: '', component: DashboardComponent },
          { path: 'stat', component: DashboardComponent },      // ✅ Statistics page
          { path: 'gestion-associations', component: GestionUsersComponent },
          { path: 'admin-valider-don', component: ValiderRefuserDonComponent },
         
      ]
  }
];
  
@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AdminLayoutRoutingModule { } 