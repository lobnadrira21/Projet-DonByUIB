import { Component, OnInit } from '@angular/core';
import * as Chartist from 'chartist';
import { CommonModule } from '@angular/common';
import { MatTooltipModule } from '@angular/material/tooltip'; 
import { AuthService } from 'app/services/auth.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'],
  imports: [CommonModule, MatTooltipModule] // ✅ Import MatTooltipModule here
})
export class DashboardComponent implements OnInit {
stats: any;
assocTypeKeys: string[] = [];
  constructor(private authService : AuthService) { }
  startAnimationForLineChart(chart){
      let seq: any, delays: any, durations: any;
      seq = 0;
      delays = 80;
      durations = 500;

      chart.on('draw', function(data) {
        if(data.type === 'line' || data.type === 'area') {
          data.element.animate({
            d: {
              begin: 600,
              dur: 700,
              from: data.path.clone().scale(1, 0).translate(0, data.chartRect.height()).stringify(),
              to: data.path.clone().stringify(),
              easing: Chartist.Svg.Easing.easeOutQuint
            }
          });
        } else if(data.type === 'point') {
              seq++;
              data.element.animate({
                opacity: {
                  begin: seq * delays,
                  dur: durations,
                  from: 0,
                  to: 1,
                  easing: 'ease'
                }
              });
          }
      });

      seq = 0;
  };
  startAnimationForBarChart(chart){
      let seq2: any, delays2: any, durations2: any;

      seq2 = 0;
      delays2 = 80;
      durations2 = 500;
      chart.on('draw', function(data) {
        if(data.type === 'bar'){
            seq2++;
            data.element.animate({
              opacity: {
                begin: seq2 * delays2,
                dur: durations2,
                from: 0,
                to: 1,
                easing: 'ease'
              }
            });
        }
      });

      seq2 = 0;
  };
   ngOnInit() {
    this.authService.getAdminStats().subscribe({
      next: (data) => {
        this.stats = data;
        console.log("Stats:", this.stats);
        if (this.stats && this.stats.association_par_type) {
        this.assocTypeKeys = Object.keys(this.stats.association_par_type);
      }
        this.initCharts();
      },
      error: (err) => {
        console.error(err);
      }
    });
  }

  initCharts() {
    // Montant par mois
    const montantData = {
      labels: ['Jan','Fév','Mar','Avr','Mai','Juin','Juil','Août','Sep','Oct','Nov','Déc'],
      series: [this.stats.montant_par_mois]
    };
    new Chartist.Line('#montantParMoisChart', montantData, {
      low: 0,
      showArea: true
    });

    // Pie Chart Associations par type
    const assocData = {
      labels: Object.keys(this.stats.association_par_type),
      series: Object.values(this.stats.association_par_type)
    };
    new Chartist.Pie('#assocTypeChart', assocData, {
      donut: true,
      donutWidth: 40,
      showLabel: false
    });
  }

}
