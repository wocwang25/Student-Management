from django.shortcuts import render, redirect
from .forms import LoginForm
from .models import Nhanvien, Lop
import hashlib

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

