# Student-Management

## KẾT NỐI BACKEND VỚI MSSQL

### Bước 0: Cài đặt môi trường
1. Cài đặt Python (phiên bản $\geq$ 3.8).
2. Cài đặt các thư viện cần thiết:
   ```
   pip install -r requirements.txt
   ```
3. Đảm bảo đã cài đặt **ODBC Driver 17 for SQL Server** trên máy. Nếu chưa, tải và cài đặt từ [Microsoft ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server).
### Bước 1: Di chuyển vào thư mục `student_management`
```
cd student_management
```
### Bước 2: Tạo tài khoản đăng nhập SQL Server
1. Mở SQL Server Management Studio (SSMS).
2. Tạo tài khoản đăng nhập (login).
3. Gắn tài khoản vào cơ sở dữ liệu `QLSVNhom`.

### Bước 3: Cấp quyền cho user
1. Mở SQL Server Management Studio (SSMS).
2. Điều hướng đến `Security` → `Login` → `<user>` (ví dụ: `test`).
3. Trong tab `General`, chọn `default database` là `QLSVNhom`.
4. Trong tab `User Mapping`, chọn `QLSVNhom` và set quyền `db_owner`.

### Bước 4: Kiểm tra kết nối cơ sở dữ liệu
1. Chạy file kiểm tra kết nối:
   ```
   python test_sqlserver.py
   ```
2. Nếu kết nối thành công, bạn sẽ thấy thông báo tương ứng.

### Bước 5: Áp dụng migrations
1. Tạo migrations
   ```
   python manage.py makemigrations
   ```
2. Kiểm tra các migrations:
   ```
   python manage.py showmigrations
   ```
3. Áp dụng migrations để tạo các bảng cần thiết:
   ```
   python manage.py migrate
   ```

### Bước 6: Chạy server
1. Khởi động server:
   ```
   python manage.py runserver
   ```
2. Truy cập ứng dụng tại [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

## Tính năng Ứng dụng Student-Management

Ứng dụng Student-Management cung cấp các chức năng sau:

1. **Quản lý sinh viên**  
   - **Danh sách sinh viên**: Hiển thị danh sách sinh viên theo từng lớp với thông tin chi tiết như mã sinh viên, họ tên, ngày sinh và địa chỉ.  
   - **Sửa thông tin sinh viên**: Cho phép chỉnh sửa các thông tin của sinh viên (họ tên, ngày sinh, địa chỉ, tên đăng nhập và mật khẩu). Quá trình cập nhật sử dụng stored procedure `SP_UPD_SINHVIEN` để xử lý các ràng buộc và cập nhật thông tin trong cơ sở dữ liệu SQL Server.
   - **Nhập điểm thi**: Cho phép nhập điểm cho sinh viên thông qua form, sau đó gọi stored procedure `SP_UPD_BANGDIEM` để lưu điểm thi vào cơ sở dữ liệu.
   - **Thêm sinh viên**: Cho phép nhân viên có quyền thêm sinh viên vào lớp học mình quản lý.
   - **Xoá sinh viên**: Cho phép nhân viên có quyền xoá sinh viên khỏi lớp học mình quản lý.

2. **Quản lý nhân viên**  
   - **Thêm nhân viên**: Hỗ trợ tạo tài khoản nhân viên quản lý bằng cách lưu thông tin vào bảng `NHANVIEN` thông qua stored procedure `SP_INS_PUBLIC_NHANVIEN`.

3. **Dashboard**  
   - **Giao diện tổng quan**: Hiển thị thông tin người dùng (nhân viên) và danh sách các lớp mà nhân viên đang quản lý. Người dùng có thể truy cập chi tiết mỗi lớp để xem danh sách sinh viên và các thao tác chỉnh sửa, nhập điểm.
   - **Xem thông tin cá nhân**: Nhân viên xác nhận lại mật khẩu để xem chi tiết thông tin cá nhân của mình bao gồm: Họ tên, Mã nhân viên, Email và Lương cơ bản.

4. **Kết nối Backend với MSSQL**  
   - **Kết nối Cơ sở dữ liệu**: Sử dụng ODBC Driver 17 for SQL Server để kết nối ứng dụng Django với cơ sở dữ liệu MSSQL.
   - **Xử lý Stored Procedure**: Ứng dụng sử dụng các stored procedure (ví dụ: `SP_UPD_SINHVIEN`, `SP_UPD_BANGDIEM`) để xử lý logic nghiệp vụ ở tầng cơ sở dữ liệu, đảm bảo tính toàn vẹn dữ liệu và xử lý các nghiệp vụ như cập nhật thông tin sinh viên, nhập điểm thi.

5. **Quyền Truy cập và Bảo mật**  
   - **Xác thực và Phân quyền**: Các trang quản lý được bảo vệ bằng các decorator kiểm tra đăng nhập (staff) và phân quyền truy cập, đảm bảo chỉ những nhân viên có đủ quyền mới có thể thao tác trên dữ liệu.

---