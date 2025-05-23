import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ListPublicationComponent } from './list-publication.component';

describe('ListPublicationComponent', () => {
  let component: ListPublicationComponent;
  let fixture: ComponentFixture<ListPublicationComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ListPublicationComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ListPublicationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
