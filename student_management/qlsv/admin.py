from django.contrib import admin
from django.contrib.auth.hashers import make_password
from django.db import connection
from django.forms import ModelForm, PasswordInput, CharField, DecimalField, FileField
from django import forms
from django.shortcuts import render, redirect
from django.urls import path
from django.http import HttpResponseRedirect
from django.contrib import messages
from .models import Nhanvien, Sinhvien, Lop, Hocphan, Bangdiem
from utils.encryption import *
from utils.key_storage import *
from decimal import Decimal
import csv
import io

# Form upload cho file CSV
class CsvImportForm(forms.Form):
    csv_file = FileField(label="Chọn file CSV")
    
# Custom Form for Nhanvien model
class NhanvienForm(ModelForm):
    # Use plain text field for password input
    password = CharField(widget=PasswordInput, required=False, label="Mật khẩu")
    
    # Use regular field for salary that will be encrypted
    luongcb = DecimalField(required=False, label="Lương cơ bản", 
                          help_text="Giá trị này sẽ được mã hóa trước khi lưu")
    
    class Meta:
        model = Nhanvien
        fields = ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password','pubkey']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Mark password as not required when editing (leave blank to keep existing)
        if self.instance.pk:
            self.fields['password'].required = False

# Custom ModelAdmin for Nhanvien
class NhanvienAdmin(admin.ModelAdmin):
    form = NhanvienForm
    list_display = ('manv', 'hoten', 'email', 'is_admin_user')
    search_fields = ('manv', 'hoten', 'email',)
    # readonly_fields = ('pubkey')
    exclude = ('pubkey',)
    change_list_template = 'admin/nhanvien_changelist.html'
    
    def is_admin_user(self, obj):
        """Check if user is admin based on naming convention"""
        return obj.tendn and obj.tendn.lower().startswith('admin_')
    is_admin_user.short_description = 'Admin'
    is_admin_user.boolean = True
    
    def get_fields(self, request, obj=None):
        """Customize displayed fields"""
        if obj:  # Editing existing object
            return ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password']
        return ['manv', 'hoten', 'email', 'luongcb', 'tendn', 'password']
    
    def save_model(self, request, obj, form, change):
        if change:  # Nếu là cập nhật nhân viên cũ
            try:
                # Lấy dữ liệu từ form
                manv = obj.manv
                luongcb = form.cleaned_data.get('luongcb')
                password = form.cleaned_data.get('password')
                
                temp_luongcb = luongcb
                form.cleaned_data['luongcb'] = None
                super().save_model(request, obj, form, change)
                form.cleaned_data['luongcb'] = temp_luongcb
                
                # Sau đó, nếu có cập nhật lương, xử lý riêng
                if luongcb is not None:
                    # Lấy public key từ database
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV=%s", [manv])
                        result = cursor.fetchone()
                        
                    if result and result[0]:
                        pubkey = result[0]
                        
                        # Mã hóa lương mới
                        encrypted_salary = encrypt_salary(luongcb, pubkey)
                        
                        # Cập nhật lương đã mã hóa vào database
                        with connection.cursor() as cursor:
                            cursor.execute(
                                "UPDATE NHANVIEN SET LUONG=%s WHERE MANV=%s",
                                [encrypted_salary, manv]
                            )
                        
                        self.message_user(request, f"Lương của nhân viên đã được mã hóa và cập nhật thành công", level='success')
                    else:
                        self.message_user(request, "Không tìm thấy khóa công khai để mã hóa lương", level='error')
                    
                return
                    
            except Exception as e:
                self.message_user(request, f"Lỗi khi cập nhật nhân viên: {str(e)}", level='error')
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
                print(public_key_pem)
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
            
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('import-csv/', self.import_csv, name='import_nhanvien_csv'),
        ]
        return custom_urls + urls
    
    def import_csv(self, request):
        if request.method == "POST":
            csv_file = request.FILES["csv_file"]
            
            # Kiểm tra định dạng file
            if not csv_file.name.endswith(('.csv', '.txt')):
                self.message_user(request, "File không đúng định dạng CSV hoặc TXT", level='error')
                return HttpResponseRedirect("..")
            
            # Đọc file
            data_set = csv_file.read().decode('utf-8')
            io_string = io.StringIO(data_set)
            
            # Bỏ qua header nếu có
            has_header = False
            first_line = next(io_string, None)
            if first_line and any(header in first_line.lower() for header in ['manv', 'mã nv']):
                has_header = True
            
            # Reset con trỏ đọc file về đầu
            io_string.seek(0)
            if has_header:
                next(io_string)
                
            successful_imports = 0
            failed_imports = 0
            error_messages = []
            
            for line_num, row in enumerate(csv.reader(io_string, delimiter=',', quotechar='"'), 1):
                # Bỏ qua dòng trống
                if not row or not ''.join(row).strip():
                    continue
                
                # Kiểm tra đủ số trường
                if len(row) < 6:
                    failed_imports += 1
                    error_messages.append(f"Dòng {line_num}: Thiếu dữ liệu")
                    continue
                
                # Lấy dữ liệu từng cột
                manv = row[0].strip()
                hoten = row[1].strip()
                email = row[2].strip() if len(row) > 2 and row[2].strip() else None
                luongcb = row[3].strip() if len(row) > 3 and row[3].strip() else None
                tendn = row[4].strip()
                password = row[5].strip()
                
                # Kiểm tra dữ liệu bắt buộc
                if not all([manv, hoten, tendn, password]):
                    failed_imports += 1
                    error_messages.append(f"Dòng {line_num}: Thiếu thông tin bắt buộc")
                    continue
                
                try:
                    # Tạo instance của model Nhanvien
                    obj = Nhanvien(
                        manv=manv,
                        hoten=hoten,
                        email=email,
                        tendn=tendn
                    )
                    
                    # Tạo mock form với cleaned_data
                    class MockForm:
                        def __init__(self, luongcb, password):
                            self.cleaned_data = {
                                'luongcb': Decimal(luongcb) if luongcb else None,
                                'password': password
                            }
                    
                    form = MockForm(luongcb, password)
                    
                    # Gọi save_model() - tái sử dụng toàn bộ logic hiện có
                    self.save_model(request, obj, form, False)  # change=False vì là thêm mới
                    
                    successful_imports += 1
                    
                except Exception as e:
                    failed_imports += 1
                    error_msg = str(e)
                    error_messages.append(f"Dòng {line_num}: {error_msg}")
            
            # Hiện thông báo kết quả
            if successful_imports > 0:
                self.message_user(request, f"Đã import thành công {successful_imports} nhân viên", level='success')
            
            if failed_imports > 0:
                errors = "<br>".join(error_messages[:10])
                if len(error_messages) > 10:
                    errors += f"<br>...và {len(error_messages) - 10} lỗi khác"
                self.message_user(request, f"Có {failed_imports} lỗi xảy ra:<br>{errors}", level='error')
            
            return HttpResponseRedirect("..")
        
        # Hiển thị form upload
        form = CsvImportForm()
        context = {
            'form': form,
            'title': 'Import nhân viên từ CSV',
            'opts': self.model._meta,
            'format_example': 'NV001, Nguyễn Văn A, nva@example.com, 10000000, nguyenvana, password123',
            'fields_description': [
                {'name': 'MANV', 'required': True},
                {'name': 'HOTEN', 'required': True},
                {'name': 'EMAIL', 'required': False},
                {'name': 'LUONGCB', 'required': False},
                {'name': 'TENDN', 'required': True},
                {'name': 'MATKHAU', 'required': True},
            ]
        }
        return render(request, 'admin/csv_form.html', context)
    
    def get_model_perms(self, request):
        self.verbose_name = "Nhân viên"
        self.verbose_name_plural = "Nhân viên"
        return super().get_model_perms(request)

# Custom ModelAdmin for other models
class LopAdmin(admin.ModelAdmin):
    # Use DB_COLUMN names instead if that's how your models are defined
    list_display = ('malop', 'ten', 'manv')
    search_fields = ('malop', 'ten')
    
    def get_tenlop(self, obj):
        # If tenlop is stored differently or needs special access
        return obj.Ten if hasattr(obj, 'Ten') else "N/A"
    get_tenlop.short_description = 'Tên lớp'

# Fix for SinhvienAdmin - using correct field names
class SinhvienAdmin(admin.ModelAdmin):
    # Adjust field names to match your model
    list_display = ('masv', 'hoten', 'malop', 'ngaysinh', 'diachi')
    list_filter = ('malop',)
    search_fields = ('masv', 'hoten')
    change_list_template = 'admin/sinhvien_changelist.html'
    
    # def get_phai(self, obj):
    #     # If phai field is stored differently
    #     return obj.phai if hasattr(obj, 'phai') else "N/A"
    # get_phai.short_description = 'Phái'
    def save_model(self, request, obj, form, change):
        if change:  # Nếu là cập nhật sinh viên cũ
            super().save_model(request, obj, form, change)
            return
            
        # Xử lý thêm sinh viên mới
        if not change:
            # Lấy dữ liệu từ form
            masv = obj.masv
            hoten = obj.hoten
            ngaysinh = obj.ngaysinh
            diachi = obj.diachi
            malop_value = obj.malop.malop if hasattr(obj.malop, 'malop') else str(obj.malop)
            tendn = obj.tendn
            password = form.cleaned_data.get('password')
            
            if not all([masv, hoten, tendn, password]):
                # Xử lý thiếu thông tin
                return
                
            try:
                hashed_password = hashing_password(password)
                # Gọi stored procedure để thêm sinh viên
                with connection.cursor() as cursor:
                    cursor.execute(
                        "EXEC SP_INS_SINHVIEN @MASV=%s, @HOTEN=%s, @NGAYSINH=%s, @DIACHI=%s, @MALOP=%s, @TENDN=%s, @MATKHAU=%s",
                        [masv, hoten, ngaysinh, diachi, malop_value, tendn, hashed_password]
                    )
                self.message_user(request, f"Sinh viên {hoten} đã được thêm thành công.", level='success')
            except Exception as e:
                self.message_user(request, f"Lỗi khi thêm sinh viên: {str(e)}", level='error')
        else:
            # Vẫn sử dụng logic mặc định cho cập nhật
            super().save_model(request, obj, form, change)
            
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('import-csv/', self.import_csv, name='import_sinhvien_csv'),
        ]
        return custom_urls + urls
    
    def import_csv(self, request):
        if request.method == "POST":
            csv_file = request.FILES["csv_file"]
            
            # Kiểm tra định dạng file
            if not csv_file.name.endswith(('.csv', '.txt')):
                self.message_user(request, "File không đúng định dạng CSV hoặc TXT", level='error')
                return HttpResponseRedirect("..")
            
            # Đọc file
            data_set = csv_file.read().decode('utf-8')
            io_string = io.StringIO(data_set)
            
            # Bỏ qua header nếu có
            has_header = False
            first_line = next(io_string, None)
            if first_line and any(header in first_line.lower() for header in ['masv', 'mã sv']):
                has_header = True
            
            # Reset con trỏ đọc file về đầu
            io_string.seek(0)
            if has_header:
                next(io_string)
                
            successful_imports = 0
            failed_imports = 0
            error_messages = []
            
            for line_num, row in enumerate(csv.reader(io_string, delimiter=',', quotechar='"'), 1):
                # Bỏ qua dòng trống
                if not row or not ''.join(row).strip():
                    continue
                
                # Kiểm tra đủ số trường
                if len(row) < 6:
                    failed_imports += 1
                    error_messages.append(f"Dòng {line_num}: Thiếu dữ liệu")
                    continue
                
                # Lấy dữ liệu từng cột
                masv = row[0].strip()
                hoten = row[1].strip()
                ngaysinh = row[2].strip() if len(row) > 2 and row[2].strip() else None
                diachi = row[3].strip() if len(row) > 3 and row[3].strip() else None
                malop = row[4].strip()
                tendn = row[5].strip()
                password = row[6].strip()
                
                # Kiểm tra dữ liệu bắt buộc
                if not all([masv, hoten, tendn, password]):
                    failed_imports += 1
                    error_messages.append(f"Dòng {line_num}: Thiếu thông tin bắt buộc")
                    continue
                
                try:
                    try:
                        lop_instance = Lop.objects.get(malop=malop)
                    except Lop.DoesNotExist:
                        raise ValueError(f"Không tìm thấy lớp với mã '{malop}'")
                    
                    # Tạo instance của model Sinhvien với đối tượng Lop
                    obj = Sinhvien(
                        masv=masv,
                        hoten=hoten,
                        ngaysinh=ngaysinh,
                        diachi=diachi,
                        malop=lop_instance,  # Gán đối tượng Lop
                        tendn=tendn
                    )
                    
                    # Tạo mock form với cleaned_data
                    class MockForm:
                        def __init__(self, password):
                            self.cleaned_data = {
                                'password': password
                            }
                    
                    form = MockForm(password)
                    
                    # Gọi save_model() - tái sử dụng toàn bộ logic hiện có
                    self.save_model(request, obj, form, False)  # change=False vì là thêm mới
                    
                    successful_imports += 1
                    
                except Exception as e:
                    failed_imports += 1
                    error_msg = str(e)
                    error_messages.append(f"Dòng {line_num}: {error_msg}")
            
            # Hiện thông báo kết quả
            if successful_imports > 0:
                self.message_user(request, f"Đã import thành công {successful_imports} sinh viên", level='success')
            
            if failed_imports > 0:
                errors = "<br>".join(error_messages[:10])
                if len(error_messages) > 10:
                    errors += f"<br>...và {len(error_messages) - 10} lỗi khác"
                self.message_user(request, f"Có {failed_imports} lỗi xảy ra:<br>{errors}", level='error')
            
            return HttpResponseRedirect("..")
        
        # Hiển thị form upload
        form = CsvImportForm()
        context = {
            'form': form,
            'title': 'Import sinh viên từ CSV',
            'opts': self.model._meta,
            'format_example': '22120001, Nguyễn Văn A, 2001-01-01, TP.HCM, CNTT, 22120001, password123',
            'fields_description': [
                {'name': 'MASV', 'required': True},
                {'name': 'HOTEN', 'required': True},
                {'name': 'NGAYSINH', 'required': False},
                {'name': 'DIACHI', 'required': False},
                {'name': 'MALOP', 'required': True},
                {'name': 'TENDN', 'required': True},
                {'name': 'MATKHAU', 'required': True},
            ]
        }
        return render(request, 'admin/csv_form.html', context)
    
    def get_model_perms(self, request):
        self.verbose_name = "Sinh viên"
        self.verbose_name_plural = "Sinh viên"
        return super().get_model_perms(request)

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