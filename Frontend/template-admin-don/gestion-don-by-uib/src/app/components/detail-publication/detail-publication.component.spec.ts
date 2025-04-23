import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DetailPublicationComponent } from './detail-publication.component';

describe('DetailPublicationComponent', () => {
  let component: DetailPublicationComponent;
  let fixture: ComponentFixture<DetailPublicationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DetailPublicationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(DetailPublicationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
