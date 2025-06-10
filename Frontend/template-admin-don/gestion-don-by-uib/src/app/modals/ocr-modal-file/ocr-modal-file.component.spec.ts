import { ComponentFixture, TestBed } from '@angular/core/testing';

import { OcrModalFileComponent } from './ocr-modal-file.component';

describe('OcrModalFileComponent', () => {
  let component: OcrModalFileComponent;
  let fixture: ComponentFixture<OcrModalFileComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [OcrModalFileComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(OcrModalFileComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
