import { ComponentFixture, TestBed } from '@angular/core/testing';

import { BottombarAssociationComponent } from './bottombar-association.component';

describe('BottombarAssociationComponent', () => {
  let component: BottombarAssociationComponent;
  let fixture: ComponentFixture<BottombarAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BottombarAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(BottombarAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
