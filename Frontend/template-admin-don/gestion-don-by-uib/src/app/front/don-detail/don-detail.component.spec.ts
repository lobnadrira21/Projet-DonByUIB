import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DonDetailComponent } from './don-detail.component';

describe('DonDetailComponent', () => {
  let component: DonDetailComponent;
  let fixture: ComponentFixture<DonDetailComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DonDetailComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(DonDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
