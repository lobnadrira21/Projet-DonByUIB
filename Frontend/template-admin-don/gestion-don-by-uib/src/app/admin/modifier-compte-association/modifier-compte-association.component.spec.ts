import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ModifierCompteAssociationComponent } from './modifier-compte-association.component';

describe('ModifierCompteAssociationComponent', () => {
  let component: ModifierCompteAssociationComponent;
  let fixture: ComponentFixture<ModifierCompteAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ModifierCompteAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ModifierCompteAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
