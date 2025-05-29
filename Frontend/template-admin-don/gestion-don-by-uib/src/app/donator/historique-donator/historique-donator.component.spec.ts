import { ComponentFixture, TestBed } from '@angular/core/testing';

import { HistoriqueDonatorComponent } from './historique-donator.component';

describe('HistoriqueDonatorComponent', () => {
  let component: HistoriqueDonatorComponent;
  let fixture: ComponentFixture<HistoriqueDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HistoriqueDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(HistoriqueDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
