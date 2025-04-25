from django import forms

class LoginForm(forms.Form):
    manv = forms.CharField(label='Mã nhân viên', max_length=20)
    password = forms.CharField(label='Mật khẩu', widget=forms.PasswordInput)