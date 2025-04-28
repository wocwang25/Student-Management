from django.db import connection
from django.http import JsonResponse
from django.shortcuts import render, redirect
from .forms import LoginForm
from .models import Nhanvien, Lop
from django.contrib import messages
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from utils.decorators import *
from decimal import Decimal

# Create your views here.
def login_view(request):
    error = ""
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            manv = form.cleaned_data['manv']
            password = form.cleaned_data['password']
            
            try:
                # Gọi SP_LOG_IN
                with connection.cursor() as cursor:
                    cursor.execute(
                        "EXEC SP_LOG_IN @MANV=%s, @MATKHAU=%s",
                        [manv, password]
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
                        
                        try:
                            nv = Nhanvien.objects.get(manv=manv)
                            request.session['pubkey'] = nv.pubkey
                        except Nhanvien.DoesNotExist:
                            # Xử lý nếu không có trong model Django
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
    
    return render(request, 'login.html', {'form': form, 'error': error})
    
def home_view(request):
    context = {}
    
    if 'manv' in request.session:
        context['hoten'] = request.session.get('hoten')
    
    return render(request, 'home.html', context)

@staff_login_required
def dashboard(request):
    # if 'manv' not in request.session:
    #     return redirect('login')
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
        messages.error(request, f"Lỗi khi lấy thông tin nhân viên: {str(e)}")
        return redirect('dashboard')
    
    employee_info = None
    error_message = None
    
    if request.method == 'POST':
        password = request.POST.get('password')
        
        try:
            # Gọi stored procedure để lấy thông tin nhân viên
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_SEL_PUBLIC_NHANVIEN @TENDN=%s, @MK=%s",
                    [tendn, password]
                )
                
                # Xử lý kết quả trả về từ stored procedure
                result = cursor.fetchone()
                if result:
                    employee_info = {
                        'manv': result[0],
                        'hoten': result[1],
                        'email': result[2],
                        'luongcb': result[3]
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
    try:
        lop = Lop.objects.get(malop=malop)
    except Lop.DoesNotExist:
        lop = {'malop': malop, 'tenlop': 'Lớp không tồn tại'}
    
    # Gọi stored procedure để lấy danh sách sinh viên
    with connection.cursor() as cursor:
        cursor.execute("EXEC SP_CL_STU @maLop=%s", [malop])
        students = cursor.fetchall()

    return render(request, 'student_list.html', {
        'students': students,
        'lop': lop
    })
    
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
            # Gọi stored procedure để thêm sinh viên
            with connection.cursor() as cursor:
                cursor.execute(
                    "EXEC SP_INS_SINHVIEN @MASV=%s, @HOTEN=%s, @NGAYSINH=%s, @DIACHI=%s, @MALOP=%s, @TENDN=%s, @MATKHAU=%s",
                    [masv, hoten, ngaysinh, diachi, malop, tendn, mk]
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
                
            messages.error(request, f"Lỗi khi thêm sinh viên: {error_message}")
            
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
                diemthi = Decimal(diemthi)
                if not (0 <= diemthi <= 10):
                    raise ValueError("Điểm phải nằm trong khoảng 0-10")
            except ValueError as e:
                messages.error(request, f"Điểm không hợp lệ: {str(e)}")
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
                    [manv, masv, mahp, diemthi]
                )
            
            # Tìm tên môn học để hiển thị thông báo
            tenhp = next((subject['tenhp'] for subject in subjects if subject['mahp'] == mahp), mahp)
            
            messages.success(request, f"Đã lưu điểm cho môn {tenhp} thành công")
            return redirect('input_score', malop=malop, masv=masv)
            
        except Exception as e:
            messages.error(request, f"Lỗi khi cập nhật điểm: {str(e)}")
    
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
                    "EXEC SP_SEL_BANGDIEM @MANV=%s, @MATKHAU=%s, @MASV=%s",
                    [manv, password, masv]
                )
                
                # Xử lý kết quả trả về từ stored procedure
                rows = cursor.fetchall()
                scores = [
                    {
                        'mahp': row[0], 
                        'tenhp': row[1], 
                        'sotc': row[2], 
                        'diemthi': row[3] if row[3] is not None else None
                    } 
                    for row in rows
                ]
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
    if request.method == 'POST':
        manv = request.session.get('manv')
        hoten = request.POST.get('hoten')
        ngaysinh = request.POST.get('ngaysinh')
        diachi = request.POST.get('diachi')
        
        tendn = request.POST.get('tendn', '')
        mk = request.POST.get('mk', '')
        tenlop = Lop.objects.filter(malop=malop).values('ten').first()['ten']
        
        if not mk:
            mk = None
        with connection.cursor() as cursor:
            cursor.execute(
                "EXEC SP_UPD_SINHVIEN @MANV=%s, @MASV=%s, @HOTEN=%s, @NGAYSINH=%s, @DIACHI=%s, @MALOP=%s, @TENDN=%s, @MATKHAU=%s, @ACTION=3",
                [manv, masv, hoten, ngaysinh, diachi, malop, tendn, mk]
            )
            
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            from django.http import JsonResponse
            return JsonResponse({'status': 'success'})
        else:
            return redirect('student_list', malop=malop)
    
    # Lấy thông tin sinh viên hiện tại để hiển thị form chỉnh sửa
    with connection.cursor() as cursor:
        cursor.execute("SELECT MASV, HOTEN, NGAYSINH, DIACHI FROM SINHVIEN WHERE MASV=%s", [masv])
        student = cursor.fetchone()
    
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

        # Lưu vào NHANVIEN
        with connection.cursor() as cursor:
            cursor.execute(
                "EXEC SP_INS_PUBLIC_NHANVIEN @MANV=%s, @HOTEN=%s, @EMAIL=%s, @LUONGCB=%s, @TENDN=%s, @MK=%s",
                [manv, hoten, email, luongcb, tendn, mk]
            )
        return redirect('class_management')
    return render(request, 'add_nhanvien.html')

@staff_login_required
def employee_list(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT MANV, HOTEN, EMAIL, LUONGCB FROM NHANVIEN")
        employees = cursor.fetchall()
    return render(request, 'employee_list.html', {'employees': employees})