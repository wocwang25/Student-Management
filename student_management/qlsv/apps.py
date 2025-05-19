from django.apps import AppConfig

class QlsvConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'qlsv'
    verbose_name = "Quản lý sinh viên"

    def ready(self):
        self.customize_models()
        
    def customize_models(self):
        """Tùy chỉnh trực tiếp tên model và trường"""
        from django.apps import apps
        
        try:
            # Lấy tất cả model trong app
            app_models = self.get_models()
            
            # Tùy chỉnh từng model
            for model in app_models:
                model_name = model.__name__
                
                # Tùy chỉnh tên model
                if model_name == 'Nhanvien':
                    model._meta.verbose_name = "Nhân viên"
                    model._meta.verbose_name_plural = "Nhân viên"
                    
                    # Tùy chỉnh các trường
                    try:
                        model._meta.get_field('manv').verbose_name = "Mã nhân viên"
                        model._meta.get_field('hoten').verbose_name = "Họ tên"
                        model._meta.get_field('email').verbose_name = "Email"
                        model._meta.get_field('luong').verbose_name = "Lương cơ bản"
                        model._meta.get_field('tendn').verbose_name = "Tên đăng nhập"
                        
                        # Kiểm tra nếu field pubkey tồn tại
                        try:
                            model._meta.get_field('pubkey').verbose_name = "Khóa công khai"
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"Lỗi khi cấu hình trường cho Nhanvien: {e}")
                
                elif model_name == 'Sinhvien':
                    model._meta.verbose_name = "Sinh viên"
                    model._meta.verbose_name_plural = "Sinh viên"
                    
                    try:
                        # Tùy chỉnh các trường
                        model._meta.get_field('masv').verbose_name = "Mã sinh viên"
                        model._meta.get_field('hoten').verbose_name = "Họ tên"
                        model._meta.get_field('ngaysinh').verbose_name = "Ngày sinh"
                        model._meta.get_field('diachi').verbose_name = "Địa chỉ"
                        model._meta.get_field('malop').verbose_name = "Mã lớp"
                        model._meta.get_field('tendn').verbose_name = "Tên đăng nhập"
                    except Exception as e:
                        print(f"Lỗi khi cấu hình trường cho Sinhvien: {e}")
                
                elif model_name == 'Lop':
                    model._meta.verbose_name = "Lớp học"
                    model._meta.verbose_name_plural = "Lớp học"
                    
                    try:
                        model._meta.get_field('malop').verbose_name = "Mã lớp"
                        model._meta.get_field('ten').verbose_name = "Tên lớp"
                        model._meta.get_field('manv').verbose_name = "Mã nhân viên"
                    except Exception as e:
                        print(f"Lỗi khi cấu hình trường cho Lop: {e}")
                
                elif model_name == 'Hocphan':
                    model._meta.verbose_name = "Học phần"
                    model._meta.verbose_name_plural = "Học phần"
                    
                    try:
                        model._meta.get_field('mahp').verbose_name = "Mã học phần"
                        model._meta.get_field('tenhp').verbose_name = "Tên học phần"
                        model._meta.get_field('sotc').verbose_name = "Số tín chỉ"
                    except Exception as e:
                        print(f"Lỗi khi cấu hình trường cho Hocphan: {e}")
                
                elif model_name == 'Bangdiem':
                    model._meta.verbose_name = "Bảng điểm"
                    model._meta.verbose_name_plural = "Bảng điểm"
                    
                    try:
                        model._meta.get_field('masv').verbose_name = "Sinh viên"
                        model._meta.get_field('mahp').verbose_name = "Học phần"
                        model._meta.get_field('diemthi').verbose_name = "Điểm thi"
                    except Exception as e:
                        print(f"Lỗi khi cấu hình trường cho Bangdiem: {e}")
        
        except Exception as e:
            print(f"Lỗi khi tùy chỉnh model: {str(e)}")