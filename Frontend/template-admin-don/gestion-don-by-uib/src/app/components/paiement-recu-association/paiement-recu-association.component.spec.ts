import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PaiementRecuAssociationComponent } from './paiement-recu-association.component';

describe('PaiementRecuAssociationComponent', () => {
  let component: PaiementRecuAssociationComponent;
  let fixture: ComponentFixture<PaiementRecuAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PaiementRecuAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(PaiementRecuAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
