import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FooterDonatorComponent } from './footer-donator.component';

describe('FooterDonatorComponent', () => {
  let component: FooterDonatorComponent;
  let fixture: ComponentFixture<FooterDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FooterDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(FooterDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
