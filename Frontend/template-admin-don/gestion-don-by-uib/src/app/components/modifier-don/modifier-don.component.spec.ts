import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ModifierDonComponent } from './modifier-don.component';

describe('ModifierDonComponent', () => {
  let component: ModifierDonComponent;
  let fixture: ComponentFixture<ModifierDonComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ModifierDonComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ModifierDonComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
