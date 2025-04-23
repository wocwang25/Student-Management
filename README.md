# Student-Management

## KẾT NỐI BACKEND VỚI MSSQL

### Bước 0: Cài đặt môi trường
1. Cài đặt Python (phiên bản >= 3.8).
2. Cài đặt các thư viện cần thiết:
   ```
   pip install -r requirements.txt
   ```
3. Đảm bảo đã cài đặt **ODBC Driver 17 for SQL Server** trên máy. Nếu chưa, tải và cài đặt từ [Microsoft ODBC Driver for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server).

### Bước 1: Tạo tài khoản đăng nhập SQL Server
1. Mở SQL Server Management Studio (SSMS).
2. Tạo tài khoản đăng nhập (login).
3. Gắn tài khoản vào cơ sở dữ liệu `QLSVNhom`.

### Bước 2: Cấp quyền cho user
1. Mở SQL Server Management Studio (SSMS).
2. Điều hướng đến `Security` → `Login` → `<user>` (ví dụ: `test`).
3. Trong tab `General`, chọn `default database` là `QLSVNhom`.
4. Trong tab `User Mapping`, chọn `QLSVNhom` và set quyền `db_owner`.

### Bước 3: Kiểm tra kết nối cơ sở dữ liệu
1. Chạy file kiểm tra kết nối:
   ```
   python test_sqlserver.py
   ```
2. Nếu kết nối thành công, bạn sẽ thấy thông báo tương ứng.

### Bước 4: Áp dụng migrations
1. Kiểm tra các migrations:
   ```
   python manage.py showmigrations
   ```
2. Áp dụng migrations để tạo các bảng cần thiết:
   ```
   python manage.py migrate
   ```

### Bước 5: Chạy server
1. Khởi động server:
   ```
   python manage.py runserver
   ```
2. Truy cập ứng dụng tại [http://127.0.0.1:8000](http://127.0.0.1:8000).

---