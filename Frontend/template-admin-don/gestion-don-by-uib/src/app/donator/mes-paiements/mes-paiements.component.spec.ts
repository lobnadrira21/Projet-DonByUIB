import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MesPaiementsComponent } from './mes-paiements.component';

describe('MesPaiementsComponent', () => {
  let component: MesPaiementsComponent;
  let fixture: ComponentFixture<MesPaiementsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MesPaiementsComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(MesPaiementsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
