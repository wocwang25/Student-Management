from django.db import connection
from django.shortcuts import render, redirect
from .forms import LoginForm
from .models import Nhanvien, Lop
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from utils.decorators import *

# Create your views here.
def login_view(request):
    error  = ""
    print("chỗ này")
    if request.method == 'POST':
        print("if")
        form = LoginForm(request.POST)
        if form.is_valid():
            tendn = form.cleaned_data['username']
            matkhau = form.cleaned_data['password']
            
            # Trong csdl, mật khẩu của nhân viên được mã hóa bằng SHA1 nên dùng này cho đồng bộ
            hashed_password = hashlib.sha1(matkhau.encode('utf-8')).digest()
            
            try:
                nv = Nhanvien.objects.get(tendn = tendn, matkhau = hashed_password)
                # Lưu session
                request.session['manv'] = nv.manv
                request.session['hoten'] = nv.hoten
                return redirect('dashboard')
            except Nhanvien.DoesNotExist:
                error = "Sai tên đăng nhập hoặc mật khẩu!"
    else:
        form = LoginForm()
    print("render")
    return render(request, 'login.html', 
                  {'form': form , 'error': error})
    
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
        classes = Lop.objects.filter(manv=nv)

        for lop in classes:
            lop.student_count = lop.sinhvien_set.count() 

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
def input_score(request, masv):
    if request.method == 'POST':
        diemthi = request.POST.get('diemthi')
        pubkey_name = request.session.get('pubkey')
        
        # Lấy public key từ NHANVIEN
        with connection.cursor() as cursor:
            cursor.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV = %s", [pubkey_name])
            pubkey_data = cursor.fetchone()[0]
            
        # Tải public key và mã hóa
        public_key = serialization.load_pem_public_key(
            pubkey_data.encode(),
            backend=default_backend()
        )
        encrypted_score = public_key.encrypt(
            diemthi.encode(),
            padding.PKCS1v15()
        )
        
        # Lưu vào BANGDIEM
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO BANGDIEM (MASV, MAHP, DIEMTHI) VALUES (%s, %s, %s)",
                [masv, 'HP001', encrypted_score]  # Giả sử MAHP cố định
            )
        return redirect('student_list')
    return render(request, 'input_score.html')

@staff_login_required
def class_management(request):
    manv = request.session['manv']
    # Truy vấn lớp do nhân viên quản lý
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM LOP WHERE MANV = %s", [manv])
        classes = cursor.fetchall()
    return render(request, 'qlsv/class_management.html', {'classes': classes})

@staff_login_required
def student_list(request, malop):
    manv = request.session.get('manv')
    try:
        # Kiểm tra lớp có thuộc quyền quản lý của nhân viên không
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT TENLOP FROM LOP WHERE MALOP = %s AND MANV = %s",
                [malop, manv]
            )
            lop_info = cursor.fetchone()
            if not lop_info:
                return render(request, 'qlsv/error.html', {'message': 'Không có quyền truy cập'})
        
        # Truy vấn sinh viên
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM SINHVIEN WHERE MALOP = %s", [malop])
            students = cursor.fetchall()
            
        return render(request, 'student_list.html', {
            'students': students,
            'tenlop': lop_info[0]
        })
        
    except Exception as e:
        return render(request, 'qlsv/error.html', {'message': f'Lỗi hệ thống: {str(e)}'})

@staff_login_required
def input_score(request, masv):
    if request.method == 'POST':
        diemthi = request.POST.get('diemthi')
        pubkey_name = request.session.get('pubkey')
        
        # Lấy public key từ NHANVIEN
        with connection.cursor() as cursor:
            cursor.execute("SELECT PUBKEY FROM NHANVIEN WHERE MANV = %s", [pubkey_name])
            pubkey_data = cursor.fetchone()[0]
            
        # Tải public key và mã hóa
        public_key = serialization.load_pem_public_key(
            pubkey_data.encode(),
            backend=default_backend()
        )
        encrypted_score = public_key.encrypt(
            diemthi.encode(),
            padding.PKCS1v15()
        )
        
        # Lưu vào BANGDIEM
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO BANGDIEM (MASV, MAHP, DIEMTHI) VALUES (%s, %s, %s)",
                [masv, 'HP001', encrypted_score]  # Giả sử MAHP cố định
            )
        return redirect('student_list', malop=masv)
    return render(request, 'qlsv/input_score.html')