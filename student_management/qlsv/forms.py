from django import forms

class LoginForm(forms.Form):
    username = forms.CharField(label='Tên đăng nhập', max_length=50)
    password = forms.CharField(label='Mật khẩu', widget=forms.PasswordInput)