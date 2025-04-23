import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SidebarDonatorComponent } from './sidebar-donator.component';

describe('SidebarDonatorComponent', () => {
  let component: SidebarDonatorComponent;
  let fixture: ComponentFixture<SidebarDonatorComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SidebarDonatorComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(SidebarDonatorComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
