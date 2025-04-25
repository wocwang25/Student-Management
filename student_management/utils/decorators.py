from functools import wraps
from django.shortcuts import redirect
from django.http import HttpResponseForbidden
from django.db import connection

def staff_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('manv'):
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def check_class_permission(view_func):
    @wraps(view_func)
    def wrapper(request, malop, *args, **kwargs):
        manv = request.session.get('manv')
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM LOP WHERE MALOP=%s AND MANV=%s",
                [malop, manv]
            )
            if cursor.fetchone()[0] == 0:
                return HttpResponseForbidden("Bạn không có quyền truy cập lớp này!")
        return view_func(request, malop, *args, **kwargs)
    return wrapper