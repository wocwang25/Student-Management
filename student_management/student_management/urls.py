"""
URL configuration for student_management project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.views.generic.base import RedirectView
from django.contrib import admin
from django.urls import path
from qlsv import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home_view, name = 'home'),
    path('favicon.ico', RedirectView.as_view(url=settings.STATIC_URL+'css/image/favicon.ico')),
    path('login/', views.login_view, name = 'login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.home_view, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', views.reset_password, name='reset_password'),    
    # path('dashboard/classes/', views.class_management, name='class_management'),
    # path('dashboard/classes/add/', views.add_class, name='add_class'),
    path('dashboard/employee/info/', views.view_employee_info, name='employee_info'),
    path('dashboard/class/<str:malop>/students/', views.student_list, name='student_list'),
    path('dashboard/class/<str:malop>/students/add/', views.add_student, name='add_student'),
    path('dashboard/class/<str:malop>/students/<str:masv>/remove/', views.remove_student, name='remove_student'),
    path('dashboard/class/<str:malop>/students/<str:masv>/score/', views.input_score, name='input_score'),
    path('dashboard/class/<str:malop>/students/<str:masv>/edit/', views.edit_student, name='edit_student'),
    path('dashboard/class/<str:malop>/students/<str:masv>/view_scores/', views.view_student_scores, name='view_student_scores')    
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
