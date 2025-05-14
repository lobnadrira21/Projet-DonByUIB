import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ValiderRefuserDonComponent } from './valider-refuser-don.component';

describe('ValiderRefuserDonComponent', () => {
  let component: ValiderRefuserDonComponent;
  let fixture: ComponentFixture<ValiderRefuserDonComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ValiderRefuserDonComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ValiderRefuserDonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
