from django.db import connection
from django.http import JsonResponse
from django.shortcuts import render, redirect
from .forms import LoginForm
from .models import Nhanvien, Lop
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.urls import reverse
from django.conf import settings
from utils.decorators import *
from utils.encryption import *
from utils.key_storage import *
from decimal import Decimal

import logging
logger = logging.getLogger('django.db.backend')

def execute_stored_procedure(proc_name, params_dict):
    logger.debug(f"EXECUTING STORED PROCEDURE: {proc_name}")
    with connection.cursor() as cursor:
        # Tạo các giá trị SQL trực tiếp với dấu nháy phù hợp
        param_strings = []
        
        for key, value in params_dict.items():
            # Xử lý giá trị theo kiểu dữ liệu để tạo chuỗi SQL hợp lệ
            if isinstance(value, str):
                formatted_value = f"N'{value}'"
            elif value is None:
                formatted_value = "NULL"
            else:
                formatted_value = str(value)
                
            param_strings.append(f"@{key}={formatted_value}")
        
        # Tạo câu lệnh SQL thực thi trực tiếp không qua tham số hóa
        exec_string = f"EXEC {proc_name} {', '.join(param_strings)}"
        
        logger.debug(f"EXECUTING RAW SQL: {exec_string}")
        
        # Thực thi trực tiếp câu lệnh không tham số hóa
        cursor.execute(exec_string)
        return cursor.fetchall()
    
# Create your views here.
def login_view(request):
    error = ""
    forgot_message = None
    forgot_success = False
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            manv = form.cleaned_data['manv']
            password = form.cleaned_data['password']           
            hashed_password = hashing_password(password)
            
            try:
                # Gọi SP_LOG_IN
                with connection.cursor() as cursor:
                    cursor.execute(
                        "EXEC SP_LOG_IN @MANV=%s, @MATKHAU=%s",
                        [manv, hashed_password]
                    )
                    result = cursor.fetchone()
                    
                    if result:  # Đăng nhập thành công
                        manv = result[0]  # MANV
                        hoten = result[1]  # HOTEN
                        email = result[2]  # EMAIL
                        
                        # Lưu thông tin vào session
                        request.session['manv'] = manv
                        request.session['hoten'] = hoten
                        request.session['email'] = email
                        
                        # Get public key if available
                        try:
                            with connection.cursor() as cursor2:
                                cursor2.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV=%s", [manv])
                                pubkey_result = cursor2.fetchone()
                                if pubkey_result:
                                    request.session['pubkey'] = pubkey_result[0]
                        except:
                            pass
                        
                        # Lưu mật khẩu tạm thời để giải mã điểm (nếu cần)
                        request.session['password_temp'] = password
                        
                        return redirect('dashboard')
            except Exception as e:
                # Bắt lỗi từ RAISERROR trong SP
                error = "Tài khoản hoặc mật khẩu không đúng!"
                print(f"Login error: {str(e)}")
    else:
        form = LoginForm()
        
    if 'forgot_message' in request.session:
        forgot_message = request.session.pop('forgot_message')
        forgot_success = request.session.pop('forgot_success', False)
    
    return render(request, 'login.html', {
        'form': form, 
        'error': error if 'error' in locals() else None,
        'forgot_message': forgot_message,
        'forgot_success': forgot_success
    })
    
def home_view(request):
    context = {}
    
    if 'manv' in request.session:
        context['hoten'] = request.session.get('hoten')
    
    return render(request, 'home.html', context)

@staff_login_required
def dashboard(request):
    manv = request.session.get('manv')
    if not manv:
        return redirect('login')
    
    try:
        nv = Nhanvien.objects.get(manv=manv)
        
        # Lấy danh sách lớp mà nhân viên đang quản lý
        classes = []
        with connection.cursor() as cursor:
            cursor.execute("EXEC SP_GET_CL @maNV=%s", [manv])
            class_rows = cursor.fetchall()
            
            # Chuyển đổi kết quả thành list các dictionary
            for row in class_rows:
                lop = {
                    'malop': row[0],
                    'ten': row[1]
                }
                
                # Tính số lượng sinh viên cho từng lớp
                cursor.execute("SELECT COUNT(*) FROM SINHVIEN WHERE MALOP=%s", [lop['malop']])
                student_count = cursor.fetchone()[0]
                lop['student_count'] = student_count
                
                classes.append(lop)

        return render(request, 'dashboard.html', {
            'nhanvien': nv,
            'classes': classes
        })

    except Nhanvien.DoesNotExist:
        error = "Không tìm thấy nhân viên"
        return render(request, 'login.html', {'error': error})


def logout_view(request):
    request.session.flush()  # Xóa toàn bộ session
    return redirect('home')

@staff_login_required
def view_employee_info(request):
    # Lấy thông tin nhân viên đang đăng nhập
    manv = request.session.get('manv')
    tendn = None
    
    # Xóa tất cả thông báo cũ
    storage = messages.get_messages(request)
    for message in storage:
        pass  # Đọc qua tất cả thông báo để đánh dấu đã đọc
    storage.used = True  # Xác nhận đã sử dụng
    
    # Lấy tên đăng nhập của nhân viên
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT TENDN FROM NHANVIEN WHERE MANV=%s", [manv])
            result = cursor.fetchone()
            if result:
                tendn = result[0]
    except Exception as e:
        messages.error(request, f"Lỗi khi lấy thông tin nhân viên: {str(e)}", extra_tags='employee_info')
        return redirect('dashboard')
    
    employee_info = None
    error_message = None
    
    if request.method == 'POST':
        password = request.POST.get('password')
        
        try:
            hashed_password = hashing_password(password)
            
            # Gọi stored procedure để lấy thông tin nhân viên
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_SEL_PUBLIC_ENCRYPT_NHANVIEN @TENDN=%s, @MK=%s",
                    [tendn, hashed_password]
                )
                
                # Xử lý kết quả trả về từ stored procedure
                result = cursor.fetchone()
                if not result:
                    error_message = "Không tìm thấy thông tin nhân viên hoặc mật khẩu không đúng"
                    return render(request, 'employee_info.html', {
                        'employee_info': None,
                        'error_message': error_message
                    })
                manv_res = result[0]
                hoten = result[1]
                email = result[2]
                encrypted_salary = result[3]
                
                pubkey = None
                with connection.cursor() as cursor:
                    cursor.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV=%s", [manv_res])
                    pubkey_result = cursor.fetchone()
                    if pubkey_result:
                        pubkey = pubkey_result[0]
                
                # Giải mã lương
                try:
                    # Lấy private key từ thư mục local
                    private_key_pem = get_private_key(manv_res)
                    
                    if not private_key_pem:
                        decrypted_salary = "Không tìm thấy private key cho nhân viên này"
                    else:
                        # Giải mã lương với private key từ local storage
                        decrypted_salary = decrypt_salary(encrypted_salary, private_key_pem, password)
                except Exception as e:
                    print(f"Lỗi giải mã: {str(e)}")
                    decrypted_salary = f"Không thể giải mã lương: {str(e)}"
                
                employee_info = {
                    'manv': manv_res,
                    'hoten': hoten,
                    'email': email,
                    'luongcb': decrypted_salary
                }
                
        except Exception as e:
            error_message = f"Lỗi khi lấy thông tin nhân viên: {str(e)}"
            print(f"Error fetching employee info: {e}")
    
    # Render template
    return render(request, 'employee_info.html', {
        'employee_info': employee_info,
        'error_message': error_message
    })

@staff_login_required
@check_class_permission
def student_list(request, malop):
    # Lấy thông tin lớp
    try:
        lop = Lop.objects.get(malop=malop)
    except Lop.DoesNotExist:
        lop = {'malop': malop, 'tenlop': 'Lớp không tồn tại'}
    
    # Lấy mã nhân viên từ session
    manv = request.session.get('manv')
    
    try:
        # Gọi stored procedure để lấy danh sách sinh viên
        with connection.cursor() as cursor:
            cursor.execute("EXEC SP_CL_STU @MALOP=%s, @MANV=%s", [malop, manv])
            students = cursor.fetchall()
        
        return render(request, 'student_list.html', {
            'students': students,
            'lop': lop
        })
            
    except Exception as e:
        error_message = str(e)
        
        # Xử lý các loại lỗi từ stored procedure
        if 'MALOP hoặc MANV không được để trống' in error_message:
            error_message = "Thiếu thông tin lớp hoặc nhân viên"
        elif 'MANV không tồn tại' in error_message:
            error_message = "Tài khoản nhân viên không hợp lệ"
        elif 'MALOP không tồn tại' in error_message:
            error_message = "Lớp không tồn tại"
        elif 'Nhân viên không có quyền truy cập thông tin lớp này' in error_message:
            error_message = "Bạn không có quyền truy cập danh sách sinh viên của lớp này"
        
        # Hiển thị thông báo lỗi
        messages.error(request, error_message, extra_tags='student_list')
        return redirect('dashboard')
    
@staff_login_required
@check_class_permission
def add_student(request, malop):
    # Lấy thông tin lớp
    try:
        lop = Lop.objects.get(malop=malop)
        tenlop = lop.ten
    except Lop.DoesNotExist:
        lop = {'malop': malop}
        with connection.cursor() as cursor:
            cursor.execute("SELECT TENLOP FROM LOP WHERE MALOP=%s", [malop])
            result = cursor.fetchone()
            tenlop = result[0] if result else 'Lớp không tồn tại'

    if request.method == 'POST':
        # Lấy dữ liệu từ form
        masv = request.POST.get('masv')
        hoten = request.POST.get('hoten')
        ngaysinh = request.POST.get('ngaysinh')
        diachi = request.POST.get('diachi')
        tendn = request.POST.get('tendn', '')
        mk = request.POST.get('mk', '')
        
        # Kiểm tra đầu vào phía server
        errors = {}
        if not masv:
            errors['masv'] = "Mã sinh viên không được để trống"
        if not hoten:
            errors['hoten'] = "Họ tên không được để trống"
        if not ngaysinh:
            errors['ngaysinh'] = "Ngày sinh không được để trống"
        if not diachi:
            errors['diachi'] = "Địa chỉ không được để trống"
        if not tendn:
            errors['tendn'] = "Tên đăng nhập không được để trống"
        if not mk:
            errors['mk'] = "Mật khẩu không được để trống"
            
        # Nếu có lỗi, trả về ngay
        if errors:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': "Vui lòng điền đầy đủ thông tin bắt buộc!",
                    'field_errors': errors
                })
            else:
                messages.error(request, "Vui lòng điền đầy đủ thông tin bắt buộc!")
                return render(request, 'add_student.html', {
                    'malop': malop,
                    'tenlop': tenlop,
                    'errors': errors
                })
        
        try:
            hashed_password = hashing_password(mk)
            # Gọi stored procedure để thêm sinh viên
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_INS_SINHVIEN @MASV=%s, @HOTEN=%s, @NGAYSINH=%s, @DIACHI=%s, @MALOP=%s, @TENDN=%s, @MATKHAU=%s",
                    [masv, hoten, ngaysinh, diachi, malop, tendn, hashed_password]
                )
            
            success_message = f"Đã thêm sinh viên {hoten} vào lớp {tenlop}"
            messages.success(request, success_message)
            
            # Nếu là AJAX request thì trả về JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'success', 
                    'message': success_message,
                    'student': {
                        'masv': masv,
                        'hoten': hoten,
                        'ngaysinh': ngaysinh,
                        'diachi': diachi
                    }
                })
                
            # Nếu không phải AJAX, chuyển hướng về danh sách sinh viên
            return redirect('student_list', malop=malop)
            
        except Exception as e:
            # Xử lý các lỗi từ stored procedure
            error_message = str(e)
            field_error = None
            
            # Xử lý các loại lỗi cụ thể
            if 'Required fields cannot be NULL' in error_message:
                error_message = "Vui lòng điền đầy đủ thông tin bắt buộc!"
            elif '@MASV is exist' in error_message:
                error_message = "Mã sinh viên đã tồn tại!"
                field_error = "masv"
            elif 'TENDN is exist' in error_message:
                error_message = "Tên đăng nhập đã tồn tại!"
                field_error = "tendn"
            elif 'MALOP does not exist' in error_message:
                error_message = "Mã lớp không tồn tại!"
                
            messages.error(request, f"Lỗi khi thêm sinh viên: {error_message}", extra_tags='add_student')
            
            # Nếu là AJAX request thì trả về JSON
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                response_data = {
                    'status': 'error', 
                    'message': error_message
                }
                
                if field_error:
                    response_data['field_error'] = field_error
                    
                return JsonResponse(response_data)
            
            # Nếu không phải AJAX, render lại form với lỗi
            return render(request, 'add_student.html', {
                'malop': malop,
                'tenlop': tenlop,
                'error': error_message,
                'form_data': {
                    'masv': masv,
                    'hoten': hoten,
                    'ngaysinh': ngaysinh,
                    'diachi': diachi,
                    'tendn': tendn
                }
            })
    
    # Render form thêm sinh viên (GET request)
    return render(request, 'add_student.html', {
        'malop': malop,
        'tenlop': tenlop
    })

@staff_login_required
@check_class_permission
def remove_student(request, malop, masv):
    # Lấy mã nhân viên từ session
    manv = request.session.get('manv')
    
    try:
        # Trước khi xóa, lấy tên sinh viên để hiển thị trong thông báo
        student_name = ""
        with connection.cursor() as cursor:
            cursor.execute("SELECT HOTEN FROM SINHVIEN WHERE MASV=%s", [masv])
            result = cursor.fetchone()
            if result:
                student_name = result[0]
        
        # Gọi stored procedure để xóa sinh viên
        with connection.cursor() as cursor:
            cursor.execute("EXEC SP_DEL_SINHVIEN @MASV=%s, @MANV=%s", [masv, manv])
            
        success_message = f"Đã xóa sinh viên {student_name} (MSSV: {masv})"
        messages.success(request, success_message)
        
        # Nếu là AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'success',
                'message': success_message
            })
            
    except Exception as e:
        error_message = str(e)
        
        # Xử lý các loại lỗi cụ thể
        if 'MASV or MANV cannot be NULL' in error_message:
            error_message = "Dữ liệu không hợp lệ để xóa sinh viên"
        elif 'MANV does not exist' in error_message:
            error_message = "Tài khoản nhân viên không hợp lệ"
        elif 'MASV does not exist' in error_message:
            error_message = "Sinh viên không tồn tại"
        elif 'Nhân viên không có quyền xóa sinh viên này' in error_message:
            error_message = "Bạn không có quyền xóa sinh viên này"
        else:
            error_message = f"Lỗi khi xóa sinh viên: {error_message}"
            
        messages.error(request, error_message)
        
        # Nếu là AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'message': error_message
            })
    
    # Mặc định redirect về trang danh sách sinh viên
    return redirect('student_list', malop=malop) 

@staff_login_required
@check_class_permission
def input_score(request, malop, masv):
    # Lấy thông tin sinh viên
    student_name = ""
    manv = request.session.get('manv')
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT HOTEN FROM SINHVIEN WHERE MASV=%s", [masv])
            result = cursor.fetchone()
            if result:
                student_name = result[0]
    except Exception as e:
        print(f"Error fetching student name: {e}")
    
    # Lấy danh sách môn học
    subjects = []
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT HP.MAHP, HP.TENHP 
                FROM HOCPHAN HP
                JOIN BANGDIEM BD ON HP.MAHP = BD.MAHP
                WHERE BD.MASV = %s
                """, [masv])
            subjects = [{'mahp': row[0], 'tenhp': row[1]} for row in cursor.fetchall()]
    except Exception as e:
        print(f"Error fetching subjects: {e}")
    
    if request.method == 'POST':
        try:
            mahp = request.POST.get('mahp')
            diemthi = request.POST.get('diemthi')
            
            # Validate
            if not mahp:
                messages.error(request, "Vui lòng chọn môn học")
                return render(request, 'input_score.html', {
                    'masv': masv, 
                    'malop': malop,
                    'student_name': student_name,
                    'subjects': subjects
                })
                
            try:
                score = Decimal(diemthi)
                if not (0 <= score <= 10):
                    raise ValueError("Điểm phải nằm trong khoảng 0-10")
            except ValueError as e:
                messages.error(request, f"Điểm không hợp lệ: {str(e)}")
                return render(request, 'input_score.html', {
                    'masv': masv, 
                    'malop': malop,
                    'student_name': student_name,
                    'subjects': subjects
                })
                
            # Get employee's pubkey
            pubkey = request.session.get('pubkey')
            
            if not pubkey:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV=%s", [manv])
                        pubkey_result = cursor.fetchone()
                        if pubkey_result and pubkey_result[0]:
                            pubkey = pubkey_result[0]
                            # Lưu vào session để sử dụng sau này
                            request.session['pubkey'] = pubkey
                except Exception as e:
                    messages.error(request, f"Không thể lấy khóa công khai của nhân viên: {str(e)}")
                    return render(request, 'input_score.html', {
                        'masv': masv, 
                        'malop': malop,
                        'student_name': student_name,
                        'subjects': subjects
                    })

            # Mã hóa điểm thi
            encrypted_score = None
            if pubkey:
                try:
                    encrypted_score = encrypt_score(diemthi, pubkey)
                except Exception as e:
                    messages.error(request, f"Lỗi mã hóa điểm: {str(e)}")
                    return render(request, 'input_score.html', {
                        'masv': masv, 
                        'malop': malop,
                        'student_name': student_name,
                        'subjects': subjects
                    })
            else:
                messages.error(request, "Không tìm thấy khóa công khai của nhân viên để mã hóa điểm.")
                return render(request, 'input_score.html', {
                    'masv': masv, 
                    'malop': malop,
                    'student_name': student_name,
                    'subjects': subjects
                })
            
            # Gọi SP để mã hóa và lưu điểm
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_UPD_BANGDIEM @MANV=%s, @MASV=%s, @MAHP=%s, @DIEMTHI=%s",
                    [manv, masv, mahp, encrypted_score]
                )
            
            # Tìm tên môn học để hiển thị thông báo
            tenhp = next((subject['tenhp'] for subject in subjects if subject['mahp'] == mahp), mahp)
            
            messages.success(request, f"Đã lưu điểm cho môn {tenhp} thành công", extra_tags='input_score')
            return redirect('input_score', malop=malop, masv=masv)
            
        except Exception as e:
            messages.error(request, f"Lỗi khi cập nhật điểm: {str(e)}", extra_tags='input_score')
    
    return render(request, 'input_score.html', {
        'masv': masv, 
        'malop': malop,
        'student_name': student_name,
        'subjects': subjects
    })
    
@staff_login_required
@check_class_permission
def view_student_scores(request, malop, masv):
    # Lấy thông tin sinh viên
    student_name = ""
    manv = request.session.get('manv')
    scores = []
    error_message = None
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT HOTEN FROM SINHVIEN WHERE MASV=%s", [masv])
            result = cursor.fetchone()
            if result:
                student_name = result[0]
    except Exception as e:
        print(f"Error fetching student name: {e}")
        
    if request.method == 'POST':
        password = request.POST.get('password')
        
        try:
            # Gọi stored procedure để xem điểm đã giải mã
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_SEL_BANGDIEM @MANV=%s, @MASV=%s",
                    [manv, masv]
                )
                
                # Lấy kết quả trả về từ stored procedure
                rows = cursor.fetchall()
                
                # Get private key from local storage
                private_key_pem = get_private_key(manv)
                
                if not private_key_pem:
                    raise ValueError("Không tìm thấy private key cho nhân viên này")
                
                # Giải mã điểm thi
                scores = []
                for row in rows:
                    try:
                        diemthi = decrypt_score(row[3], private_key_pem, password) if row[3] else "Chưa có điểm"
                    except Exception as e:
                        diemthi = "Không thể giải mã điểm: " + str(e)
                    scores.append({
                        'mahp': row[0],
                        'tenhp': row[1],
                        'sotc': row[2],
                        'diemthi': diemthi,
                    })
        except Exception as e:
            error_message = f"Lỗi khi lấy điểm: {str(e)}"
            print(f"Error fetching scores: {e}")
            
    # Nếu là AJAX request, trả về JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        from django.http import JsonResponse
        if error_message:
            return JsonResponse({'status': 'error', 'message': error_message})
        return JsonResponse({
            'status': 'success',
            'scores': scores
        })
    
    # Nếu không phải AJAX, render template thông thường
    return render(request, 'view_scores.html', {
        'masv': masv,
        'malop': malop,
        'student_name': student_name,
        'scores': scores,
        'error_message': error_message
    })


@staff_login_required
@check_class_permission
def edit_student(request, malop, masv):
    # Lấy tên lớp để hiển thị
    try:
        tenlop = Lop.objects.filter(malop=malop).values('ten').first()['ten']
    except:
        tenlop = "Không xác định"
    
    if request.method == 'POST':
        manv = request.session.get('manv')
        hoten = request.POST.get('hoten')
        ngaysinh = request.POST.get('ngaysinh')
        diachi = request.POST.get('diachi')
        tendn = request.POST.get('tendn', '')
        mk = request.POST.get('mk', '')
        
        # Xử lý trường hợp mật khẩu trống
        if not mk:
            hashed_password = None
        else:
            hashed_password = hashing_password(mk)
            
        try:
            # Gọi stored procedure để cập nhật sinh viên
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_UPD_SINHVIEN @MANV=%s, @MASV=%s, @HOTEN=%s, @NGAYSINH=%s, @DIACHI=%s, @MALOP=%s, @TENDN=%s, @MATKHAU=%s",
                    [manv, masv, hoten, ngaysinh, diachi, malop, tendn, hashed_password]
                )
            
            messages.success(request, f"Đã cập nhật thông tin sinh viên {hoten} thành công!", extra_tags='edit_student')
            
            # Xử lý AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'success',
                    'message': f"Đã cập nhật thông tin sinh viên {hoten} thành công!"
                })
            else:
                return redirect('student_list', malop=malop)
                
        except Exception as e:
            error_message = str(e)
            
            # Xử lý các loại lỗi từ stored procedure
            if 'MASV hoặc MANV không được để trống' in error_message:
                error_message = "Thiếu thông tin sinh viên hoặc nhân viên"
            elif 'MANV không tồn tại' in error_message:
                error_message = "Tài khoản nhân viên không hợp lệ"
            elif 'MASV không tồn tại' in error_message:
                error_message = "Sinh viên không tồn tại"
            elif 'Nhân viên không có quyền cập nhật thông tin cho sinh viên này' in error_message:
                error_message = "Bạn không có quyền cập nhật thông tin cho sinh viên này"
            elif 'HOTEN không được để trống' in error_message:
                error_message = "Họ tên không được để trống"
            elif 'TENDN đã tồn tại' in error_message:
                error_message = "Tên đăng nhập đã tồn tại"
            elif 'MALOP không tồn tại' in error_message:
                error_message = "Lớp không tồn tại"
            
            messages.error(request, f"Lỗi: {error_message}", extra_tags='edit_student')
            
            # Xử lý AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'status': 'error',
                    'message': error_message
                })
    
    # Lấy thông tin sinh viên hiện tại để hiển thị form chỉnh sửa
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT MASV, HOTEN, NGAYSINH, DIACHI, TENDN FROM SINHVIEN WHERE MASV=%s", [masv])
            student = cursor.fetchone()
        
        if not student:
            messages.error(request, "Không tìm thấy sinh viên")
            return redirect('student_list', malop=malop)
    except Exception as e:
        messages.error(request, f"Lỗi khi lấy thông tin sinh viên: {str(e)}", extra_tags='edit_student')
        return redirect('student_list', malop=malop)
    
    # Render template chỉnh sửa sinh viên
    return render(request, 'student_list.html', {
        'students': student,
        'lop': {'malop': malop, 'tenlop': tenlop}
    })

@staff_login_required
def add_employee(request):
    if request.method == 'POST':
        manv = request.POST.get('manv')
        hoten = request.POST.get('hoten')
        email = request.POST.get('email')
        luongcb = request.POST.get('luongcb')
        tendn = request.POST.get('tendn')
        mk = request.POST.get('mk')

        try:
            # Generate RSA key pair for the employee
            private_key, public_key, public_key_pem = generate_key_pair()
            
            # Hash the password
            hashed_password = hashing_password(mk)
            
            # Encrypt the salary using the public key
            encrypted_salary = encrypt_salary(luongcb, public_key_pem)
            
            # Save employee information including the public key
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_INS_PUBLIC_NHANVIEN @MANV=%s, @HOTEN=%s, @EMAIL=%s, @LUONGCB=%s, @TENDN=%s, @MK=%s, @PUBKEY=%s",
                    [manv, hoten, email, encrypted_salary, tendn, hashed_password, public_key_pem]
                )
            
            # Save private key locally
            private_key_pem = private_key.export_key().decode('utf-8')
            save_result = save_private_key(manv, private_key_pem)
            
            if save_result:
                messages.success(request, f"Nhân viên {hoten} đã được thêm thành công. Khóa bí mật được lưu cục bộ.")
            else:
                messages.warning(request, f"Nhân viên {hoten} đã được thêm nhưng không thể lưu khóa bí mật.")
            
            return redirect('employee_list')
            
        except Exception as e:
            messages.error(request, f"Lỗi khi thêm nhân viên: {str(e)}")
            # Return to form with entered data
            return render(request, 'add_nhanvien.html', {
                'form_data': {
                    'manv': manv,
                    'hoten': hoten,
                    'email': email,
                    'luongcb': luongcb,
                    'tendn': tendn
                }
            })
            
    return render(request, 'add_nhanvien.html')

@staff_login_required
def employee_list(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT MANV, HOTEN, EMAIL FROM NHANVIEN")
        employees = cursor.fetchall()
    return render(request, 'employee_list.html', {'employees': employees})

# Hàm xử lý quên mật khẩu
def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            # Kiểm tra email có tồn tại trong hệ thống
            with connection.cursor() as cursor:
                cursor.execute("SELECT MANV FROM NHANVIEN WHERE EMAIL=%s", [email])
                result = cursor.fetchone()
                if not result:
                    messages.error(request, "Email không tồn tại trong hệ thống.")
                    return redirect('forgot_password')
                
                manv = result[0]  # Lấy mã nhân viên
                
                # Tạo token reset mật khẩu
                token = get_random_string(32)
                reset_url = request.build_absolute_uri(reverse('reset_password', args=[token]))
                
                # Lưu token và thông tin nhân viên vào session
                request.session['reset_token'] = token
                request.session['reset_email'] = email
                request.session['reset_manv'] = manv
                
                # Gửi email reset mật khẩu
                send_mail(
                    'Reset mật khẩu',
                    f'Nhấn vào liên kết sau để đặt lại mật khẩu: {reset_url}',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                messages.success(request, "Email đặt lại mật khẩu đã được gửi.")
                return redirect('login')
        except Exception as e:
            messages.error(request, f"Lỗi: {str(e)}")
            return redirect('forgot_password')
    
    return render(request, 'forgot_password.html')

# Hàm xử lý đặt lại mật khẩu
def reset_password(request, token):
    # Kiểm tra token
    session_token = request.session.get('reset_token')
    email = request.session.get('reset_email')
    manv = request.session.get('reset_manv')
    
    if not session_token or session_token != token or not email or not manv:
        messages.error(request, "Token không hợp lệ hoặc đã hết hạn.")
        return redirect('forgot_password')
    
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password != confirm_password:
            messages.error(request, "Mật khẩu xác nhận không khớp.")
            return redirect('reset_password', token=token)
        
        try:
            hashed_password = hashing_password(new_password)
            # Sử dụng stored procedure để reset mật khẩu
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_RESET_PASSWORD_NHANVIEN @MANV=%s, @EMAIL=%s, @NewPassword=%s",
                    [manv, email, hashed_password]
                )
            
            # Xóa dữ liệu reset khỏi session
            for key in ['reset_token', 'reset_email', 'reset_manv']:
                if key in request.session:
                    del request.session[key]
            
            messages.success(request, "Mật khẩu đã được đặt lại thành công.")
            return redirect('login')
            
        except Exception as e:
            error_message = str(e)
            
            # Xử lý các loại lỗi từ stored procedure
            if 'MANV, EMAIL hoặc NewPassword không được để trống' in error_message:
                error_message = "Thiếu thông tin để đặt lại mật khẩu."
            elif 'MANV hoặc EMAIL không đúng' in error_message:
                error_message = "Thông tin nhân viên không chính xác."
            elif 'Mật khẩu mới phải có ít nhất 8 ký tự' in error_message:
                error_message = "Mật khẩu mới phải có ít nhất 8 ký tự."
            
            messages.error(request, f"Lỗi: {error_message}")
            return redirect('reset_password', token=token)
    
    return render(request, 'reset_password.html', {'token': token})