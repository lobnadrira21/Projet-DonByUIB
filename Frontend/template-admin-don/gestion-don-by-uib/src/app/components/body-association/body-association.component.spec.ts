import { ComponentFixture, TestBed } from '@angular/core/testing';

import { BodyAssociationComponent } from './body-association.component';

describe('BodyAssociationComponent', () => {
  let component: BodyAssociationComponent;
  let fixture: ComponentFixture<BodyAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BodyAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(BodyAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
