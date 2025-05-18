from django.contrib import admin
from django.contrib.auth.hashers import make_password
from django.db import connection
from django.forms import ModelForm, PasswordInput, CharField, DecimalField
from .models import Nhanvien, Sinhvien, Lop, Hocphan, Bangdiem
from utils.encryption import *
from utils.key_storage import *
from decimal import Decimal

# Custom Form for Nhanvien model
class NhanvienForm(ModelForm):
    # Use plain text field for password input
    password = CharField(widget=PasswordInput, required=False, label="Mật khẩu")
    
    # Use regular field for salary that will be encrypted
    luongcb = DecimalField(required=False, label="Lương cơ bản", 
                          help_text="Giá trị này sẽ được mã hóa trước khi lưu")
    
    class Meta:
        model = Nhanvien
        fields = ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Mark password as not required when editing (leave blank to keep existing)
        if self.instance.pk:
            self.fields['password'].required = False

# Custom ModelAdmin for Nhanvien
class NhanvienAdmin(admin.ModelAdmin):
    form = NhanvienForm
    list_display = ('manv', 'hoten', 'email', 'tendn', 'is_admin_user')
    search_fields = ('manv', 'hoten', 'email', 'tendn')
    readonly_fields = ('pubkey',)
    
    def is_admin_user(self, obj):
        """Check if user is admin based on naming convention"""
        return obj.tendn and obj.tendn.lower().startswith('admin_')
    is_admin_user.short_description = 'Admin'
    is_admin_user.boolean = True
    
    def get_fields(self, request, obj=None):
        """Customize displayed fields"""
        if obj:  # Editing existing object
            return ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password', 'pubkey']
        return ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password']
    
    def save_model(self, request, obj, form, change):
        if change:  # Nếu là cập nhật nhân viên cũ
            super().save_model(request, obj, form, change)
            return
            
        # Xử lý thêm nhân viên mới
        if not change:
            # Lấy dữ liệu từ form
            manv = obj.manv
            hoten = obj.hoten
            email = obj.email
            tendn = obj.tendn
            luongcb = form.cleaned_data.get('luongcb')
            password = form.cleaned_data.get('password')
            
            if not all([manv, hoten, tendn, password]):
                # Xử lý thiếu thông tin
                return
                
            try:
                # Tạo cặp khóa
                private_key, public_key, public_key_pem = generate_key_pair()
                
                # Hash mật khẩu
                hashed_password = hashing_password(password)
                
                # Mã hóa lương
                encrypted_salary = None
                if luongcb:
                    encrypted_salary = encrypt_salary(luongcb, public_key_pem)
                    
                # Serialize private key WITH password protection
                protected_private_key = serialize_private_key(private_key, password)
                
                # Gọi stored procedure để thêm nhân viên
                with connection.cursor() as cursor:
                    cursor.execute(
                        "EXEC SP_INS_PUBLIC_ENCRYPT_NHANVIEN @MANV=%s, @HOTEN=%s, @EMAIL=%s, @LUONGCB=%s, @TENDN=%s, @MK=%s, @PUBKEY=%s",
                        [manv, hoten, email, encrypted_salary, tendn, hashed_password, public_key_pem]
                    )
                
                # Lưu private key ĐÃ ĐƯỢC BẢO VỆ
                save_result = save_private_key(manv, protected_private_key)
                
                if save_result:
                    self.message_user(request, f"Nhân viên {hoten} đã được thêm thành công. Khóa bí mật được bảo vệ bằng mật khẩu.", level='success')
                else:
                    self.message_user(request, f"Nhân viên đã được thêm nhưng không thể lưu khóa bí mật.", level='warning')
                                    
            except Exception as e:
                self.message_user(request, f"Lỗi khi thêm nhân viên: {str(e)}", level='error')
        else:
            # Vẫn sử dụng logic mặc định cho cập nhật
            super().save_model(request, obj, form, change)

# Custom ModelAdmin for other models
class LopAdmin(admin.ModelAdmin):
    # Use DB_COLUMN names instead if that's how your models are defined
    list_display = ('malop', 'get_tenlop', 'manv')
    search_fields = ('malop', 'tenlop')
    
    def get_tenlop(self, obj):
        # If tenlop is stored differently or needs special access
        return obj.tenlop if hasattr(obj, 'tenlop') else "N/A"
    get_tenlop.short_description = 'Tên lớp'

# Fix for SinhvienAdmin - using correct field names
class SinhvienAdmin(admin.ModelAdmin):
    # Adjust field names to match your model
    list_display = ('masv', 'hoten', 'get_phai', 'malop')
    list_filter = ('malop',)  # Remove 'phai' from list_filter temporarily
    search_fields = ('masv', 'hoten')
    
    def get_phai(self, obj):
        # If phai field is stored differently
        return obj.phai if hasattr(obj, 'phai') else "N/A"
    get_phai.short_description = 'Phái'

class HocphanAdmin(admin.ModelAdmin):
    list_display = ('mahp', 'tenhp', 'sotc')
    search_fields = ('mahp', 'tenhp')

class BangdiemAdmin(admin.ModelAdmin):
    list_display = ('masv', 'mahp', 'diemthi')
    list_filter = ('mahp',)
    search_fields = ('masv', 'mahp')

# Register models with custom admin classes
admin.site.register(Nhanvien, NhanvienAdmin)
admin.site.register(Sinhvien, SinhvienAdmin)
admin.site.register(Lop, LopAdmin)
admin.site.register(Hocphan, HocphanAdmin)
admin.site.register(Bangdiem, BangdiemAdmin)