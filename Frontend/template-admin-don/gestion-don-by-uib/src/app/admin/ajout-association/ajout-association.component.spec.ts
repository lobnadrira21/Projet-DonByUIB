import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AjoutAssociationComponent } from './ajout-association.component';

describe('AjoutAssociationComponent', () => {
  let component: AjoutAssociationComponent;
  let fixture: ComponentFixture<AjoutAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AjoutAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(AjoutAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
