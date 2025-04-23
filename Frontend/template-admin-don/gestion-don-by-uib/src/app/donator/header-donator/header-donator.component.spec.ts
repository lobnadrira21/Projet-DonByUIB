import { ComponentFixture, TestBed } from '@angular/core/testing';

import { HeaderDonatorComponent } from './header-donator.component';

describe('HeaderDonatorComponent', () => {
  let component: HeaderDonatorComponent;
  let fixture: ComponentFixture<HeaderDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [HeaderDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(HeaderDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
