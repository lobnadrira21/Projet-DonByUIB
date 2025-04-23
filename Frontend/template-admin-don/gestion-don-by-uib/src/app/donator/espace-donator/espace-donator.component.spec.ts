import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EspaceDonatorComponent } from './espace-donator.component';

describe('EspaceDonatorComponent', () => {
  let component: EspaceDonatorComponent;
  let fixture: ComponentFixture<EspaceDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EspaceDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(EspaceDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
