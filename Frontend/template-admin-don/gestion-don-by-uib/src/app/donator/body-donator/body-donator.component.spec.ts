import { ComponentFixture, TestBed } from '@angular/core/testing';

import { BodyDonatorComponent } from './body-donator.component';

describe('BodyDonatorComponent', () => {
  let component: BodyDonatorComponent;
  let fixture: ComponentFixture<BodyDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BodyDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(BodyDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
