import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ValiderRefuserPublicationComponent } from './valider-refuser-publication.component';

describe('ValiderRefuserPublicationComponent', () => {
  let component: ValiderRefuserPublicationComponent;
  let fixture: ComponentFixture<ValiderRefuserPublicationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ValiderRefuserPublicationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ValiderRefuserPublicationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
