import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EspaceAssociationComponent } from './espace-association.component';

describe('EspaceAssociationComponent', () => {
  let component: EspaceAssociationComponent;
  let fixture: ComponentFixture<EspaceAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EspaceAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(EspaceAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
