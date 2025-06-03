import { Component, OnInit, ElementRef } from '@angular/core';

import {CommonModule, Location, LocationStrategy, PathLocationStrategy} from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { AuthService } from 'app/services/auth.service';
import { ROUTES } from '../sidemenu-association/sidemenu-association.component';
@Component({
  selector: 'app-topbar-association',
  standalone: true,
  imports: [RouterModule, CommonModule],
  templateUrl: './topbar-association.component.html',
  styleUrl: './topbar-association.component.scss'
})
export class TopbarAssociationComponent implements OnInit {
  private listTitles: any[];
  notifications: any[] = [];
  location: Location;
    mobile_menu_visible: any = 0;
  private toggleButton: any;
  private sidebarVisible: boolean;
  associationName: string = ''; 

  constructor(location: Location,  private element: ElementRef, private router: Router,private authService: AuthService) {
    this.location = location;
        this.sidebarVisible = false;
  }

  ngOnInit(){
    this.listTitles = ROUTES.filter(listTitle => listTitle);
    const navbar: HTMLElement = this.element.nativeElement;
    this.toggleButton = navbar.getElementsByClassName('navbar-toggler')[0];
    this.router.events.subscribe((event) => {
      this.sidebarClose();
       var $layer: any = document.getElementsByClassName('close-layer')[0];
       if ($layer) {
         $layer.remove();
         this.mobile_menu_visible = 0;
       }
   });

   this.authService.getProfile().subscribe({
    next: (data) => {
      this.associationName = data.nom_complet;
    },
    error: (err) => {
      console.error('Erreur lors du chargement du nom :', err);
    }
  });

  this.router.events.subscribe((event) => {
    this.sidebarClose();
    var $layer: any = document.getElementsByClassName('close-layer')[0];
    if ($layer) {
      $layer.remove();
      this.mobile_menu_visible = 0;
    }
  });
// Supprimer les notifications de plus de 24h (appel backend)
 this.authService.cleanupOldNotifications().subscribe({
      next: (res) => {
        console.log("🧹 Notifications anciennes nettoyées :", res);

        // Étape 2 : Récupérer les notifications à jour
        this.loadFreshNotifications();
      },
      error: (err) => {
        console.error("Erreur lors du nettoyage des notifications :", err);
        this.loadFreshNotifications();  // Charger quand même
      }
    });
  }

  loadFreshNotifications() {
    this.authService.getNotifications().subscribe({
      next: (data) => {
        // ✅ Supprime côté Angular les notifs de + de 24h (juste au cas où)
        const now = new Date();
        this.notifications = data.filter((notif: any) => {
          const notifDate = new Date(notif.date);
          const diffHours = (now.getTime() - notifDate.getTime()) / (1000 * 60 * 60);
          return diffHours <= 24;
        });

        console.log("🔔 Notifications récentes affichées :", this.notifications);
      },
      error: (err) => console.error('Erreur lors du chargement des notifications :', err)
    });
  }

  sidebarOpen() {
      const toggleButton = this.toggleButton;
      const body = document.getElementsByTagName('body')[0];
      setTimeout(function(){
          toggleButton.classList.add('toggled');
      }, 500);

      body.classList.add('nav-open');

      this.sidebarVisible = true;
  };
  sidebarClose() {
      const body = document.getElementsByTagName('body')[0];
      this.toggleButton.classList.remove('toggled');
      this.sidebarVisible = false;
      body.classList.remove('nav-open');
  };
  sidebarToggle() {
      // const toggleButton = this.toggleButton;
      // const body = document.getElementsByTagName('body')[0];
      var $toggle = document.getElementsByClassName('navbar-toggler')[0];

      if (this.sidebarVisible === false) {
          this.sidebarOpen();
      } else {
          this.sidebarClose();
      }
      const body = document.getElementsByTagName('body')[0];

      if (this.mobile_menu_visible == 1) {
          // $('html').removeClass('nav-open');
          body.classList.remove('nav-open');
          if ($layer) {
              $layer.remove();
          }
          setTimeout(function() {
              $toggle.classList.remove('toggled');
          }, 400);

          this.mobile_menu_visible = 0;
      } else {
          setTimeout(function() {
              $toggle.classList.add('toggled');
          }, 430);

          var $layer = document.createElement('div');
          $layer.setAttribute('class', 'close-layer');


          if (body.querySelectorAll('.main-panel')) {
              document.getElementsByClassName('main-panel')[0].appendChild($layer);
          }else if (body.classList.contains('off-canvas-sidebar')) {
              document.getElementsByClassName('wrapper-full-page')[0].appendChild($layer);
          }

          setTimeout(function() {
              $layer.classList.add('visible');
          }, 100);

          $layer.onclick = function() { //asign a function
            body.classList.remove('nav-open');
            this.mobile_menu_visible = 0;
            $layer.classList.remove('visible');
            setTimeout(function() {
                $layer.remove();
                $toggle.classList.remove('toggled');
            }, 400);
          }.bind(this);

          body.classList.add('nav-open');
          this.mobile_menu_visible = 1;

      }
  };

  getTitle(){
    var titlee = this.location.prepareExternalUrl(this.location.path());
    if(titlee.charAt(0) === '#'){
        titlee = titlee.slice( 1 );
    }

    for(var item = 0; item < this.listTitles.length; item++){
        if(this.listTitles[item].path === titlee){
            return this.listTitles[item].title;
        }
    }
    return 'Dashboard';
  }

  logout() {
    this.authService.logout(); // Call the logout function from AuthService
  }

}
