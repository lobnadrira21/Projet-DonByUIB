import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TopbarAssociationComponent } from './topbar-association.component';

describe('TopbarAssociationComponent', () => {
  let component: TopbarAssociationComponent;
  let fixture: ComponentFixture<TopbarAssociationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TopbarAssociationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(TopbarAssociationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
