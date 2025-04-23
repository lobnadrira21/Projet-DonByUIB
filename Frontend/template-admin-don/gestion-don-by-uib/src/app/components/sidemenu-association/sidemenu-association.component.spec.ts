import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SidemenuAssociationComponent } from './sidemenu-association.component';

describe('SidemenuAssociationComponent', () => {
  let component: SidemenuAssociationComponent;
  let fixture: ComponentFixture<SidemenuAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SidemenuAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(SidemenuAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
