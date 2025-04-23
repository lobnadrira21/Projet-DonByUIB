import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ParticiperDonComponent } from './participer-don.component';

describe('ParticiperDonComponent', () => {
  let component: ParticiperDonComponent;
  let fixture: ComponentFixture<ParticiperDonComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ParticiperDonComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ParticiperDonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
