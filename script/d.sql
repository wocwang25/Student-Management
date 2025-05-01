-- Câu d

--SP cho màn hình đăng nhập
if exists (select 1 from sys.procedures where name = 'SP_LOG_IN')
begin
	drop proc SP_LOG_IN
end
go

create proc SP_LOG_IN
(
	@MANV varchar(20),
	@MATKHAU varchar(50)
)
as
begin
	set nocount on;

	-- Băm mật khẩu SHA1 (cho nhân viên)
	declare @EnPassSHA1 varbinary(max);
	set @EnPassSHA1 = hashbytes('SHA1', @MATKHAU);

	-- Kiểm tra đăng nhập cho nhân viên
    if exists (select 1 from NHANVIEN where MANV = @MANV and MATKHAU = @EnPassSHA1)
    begin
        -- Trả về thông tin nhân viên nếu thành công
        select MANV, HOTEN, EMAIL
        from NHANVIEN
        where MANV = @MANV and MATKHAU = @EnPassSHA1;
    end
    else
    begin
        -- Thông báo lỗi nếu thất bại
        raiserror(N'Tên đăng nhập/id hoặc mật khẩu không đúng', 16, 1);
    end
end
go

-- Thêm sinh viên
if exists (select 1 from sys.procedures where name = 'SP_INS_SINHVIEN')
begin
	drop proc SP_INS_SINHVIEN
end
go

create proc SP_INS_SINHVIEN
(
	@MASV varchar(20),
	@HOTEN nvarchar(100),
	@NGAYSINH datetime,
	@DIACHI nvarchar(200),
	@MALOP varchar(20),
	@TENDN nvarchar(100),
	@MATKHAU varchar(50)
)
as
begin
	set nocount on;

	-- Kiểm tra các cột bắt buộc
	if @MASV is null or @HOTEN is null or @TENDN is null or @MATKHAU is null
	begin
		raiserror(N'Các trường dữ liệu cần thiết không được để trống', 16, 1);
		return;
	end

	-- Kiểm tra sinh viên đã tồn tại hay chưa
	if exists (select 1 from SINHVIEN where MASV = @MASV)
	begin
		raiserror(N'@MASV đã tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra TENDN đã tồn tại
	if exists (select 1 from SINHVIEN where TENDN = @TENDN)
	begin
		raiserror(N'TENDN đã tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra MALOP tồn tại
	if @MALOP is not null and not exists (select 1 from LOP where MALOP = @MALOP)
	begin
		raiserror(N'MALOP không tồn tại', 16, 1);
		return;
	end

	-- Băm mật khẩu bằng MD5
	declare @HashPass varbinary(max);
	set @HashPass = hashbytes('MD5', @MATKHAU);

	-- Thêm dữ liệu
	insert into SINHVIEN (MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN, MATKHAU)
	values (@MASV, @HOTEN, @NGAYSINH, @DIACHI, @MALOP, @TENDN, @HashPass);
end
go

--drop procedure SP_INS_SINHVIEN
go

-- Cập nhật thông tin sinh viên
if exists (select 1 from sys.procedures where name = 'SP_UPD_SINHVIEN')
begin
	drop proc SP_UPD_SINHVIEN
end
go

create procedure SP_UPD_SINHVIEN
(
	@MANV varchar(20),
	@MASV varchar(20),
	@HOTEN nvarchar(100),
	@NGAYSINH datetime,
	@DIACHI nvarchar(200),
	@MALOP varchar(20),
	@TENDN nvarchar(100),
	@MATKHAU varchar(50)
)
as
begin
	set nocount on;
	
	-- Kiểm tra đầu vào
	if @MASV is null or @MANV is null
	begin
		raiserror(N'MASV hoặc MANV không được để trống', 16, 1);
		return;
	end

	-- Kiểm tra nhân viên có tồn tại
	if not exists (select 1 from NHANVIEN where MANV = @MANV)
	begin
		raiserror(N'MANV không tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra sinh viên có tồn tại
	if not exists (select 1 from SINHVIEN where MASV = @MASV)
	begin
		raiserror(N'MASV không tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra quyền: nhân viên phải quản lý lớp của sinh viên
	declare @COUNT int;
	set @COUNT = (
		select count(*)
		from SINHVIEN SV
		inner join LOP L on SV.MALOP = L.MALOP
		where SV.MASV = @MASV and L.MANV = @MANV
	);

	if @COUNT = 0
	begin
		raiserror(N'Nhân viên không có quyền cập nhật thông tin cho sinh viên này', 16, 1);
		return;
	end

	-- Kiểm tra HOTEN không null
    if @HOTEN is null
    begin
        raiserror(N'HOTEN không được để trống', 16, 1);
        return;
    end

    -- Kiểm tra TENDN mới không trùng (nếu cung cấp)
    if @TENDN is not null and @TENDN <> '' and exists (
		select 1 from SINHVIEN
		where TENDN = @TENDN and MASV <> @MASV
    )
    begin
        raiserror(N'TENDN đã tồn tại', 16, 1);
        return;
    end

    -- Kiểm tra MALOP tồn tại (nếu cung cấp)
    if @MALOP is not null and not exists (select 1 from LOP where MALOP = @MALOP)
    begin
        raiserror(N'MALOP không tồn tại', 16, 1);
        return;
    end

	-- Chỉnh sửa thông tin của sinh viên
	declare @EnKey varbinary(max);
	declare @Old_hash varbinary(max);
	declare @Old_tendn nvarchar(100);
        
	-- Lấy giá trị hiện có của tên đăng nhập và mật khẩu
	select @Old_hash = MATKHAU, @Old_tendn = TENDN 
	from SINHVIEN 
	where MASV = @MASV;

	-- Xử lý mật khẩu: nếu @MATKHAU không được nhập thì giữ nguyên giá trị cũ
	if @MATKHAU is null or @MATKHAU = ''
	begin
		set @EnKey = @Old_hash;
	end
	else
	begin
		set @EnKey = hashbytes('MD5', @MATKHAU);
	end

	-- Cập nhật thông tin sinh viên
	begin try
		update SINHVIEN
		set
			HOTEN = @HOTEN,
			NGAYSINH = @NGAYSINH,
			DIACHI = @DIACHI,
			MALOP = @MALOP,
			TENDN = case when @TENDN is null or @TENDN = '' then @Old_tendn else @TENDN end,
			MATKHAU = @EnKey
		where
			MASV = @MASV;
		-- Trả về bản ghi vừa cập nhật
		select * from SINHVIEN where MALOP = @MALOP;
	end try
	begin catch
		declare @ErrorMessage nvarchar(max) = error_message();
        raiserror(N'Lỗi khi cập nhật sinh viên: %s', 16, 1, @ErrorMessage);
        return;
	end catch
end
go

--drop procedure SP_UPD_SINHVIEN
go

-- Xoá sinh viên
if exists (select 1 from sys.procedures where name = 'SP_DEL_SINHVIEN')
begin
	drop proc SP_DEL_SINHVIEN
end
go

create proc SP_DEL_SINHVIEN
(
	@MASV varchar(20),
	@MANV varchar(20)
)
as
begin
	set nocount on;

	-- Kiểm tra đầu vào
	if @MASV is null or @MANV is null
	begin
		raiserror(N'MASV hoặc MANV không được để trống', 16, 1);
		return;
	end

	-- Kiểm tra nhân viên có tồn tại
	if not exists (select 1 from NHANVIEN where MANV = @MANV)
	begin
		raiserror(N'MANV không tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra sinh viên có tồn tại
	if not exists (select 1 from SINHVIEN where MASV = @MASV)
	begin
		raiserror(N'MASV không tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra quyền: nhân viên phải quản lý lớp của sinh viên
	declare @COUNT int;
	set @COUNT = (
		select count(*)
		from SINHVIEN SV
		inner join LOP L on SV.MALOP = L.MALOP
		where SV.MASV = @MASV and L.MANV = @MANV
	);

	if @COUNT = 0
	begin
		raiserror(N'Nhân viên không có quyền xóa sinh viên này', 16, 1);
		return;
	end

	-- Xóa sinh viên
	begin try
		delete from SINHVIEN
		where MASV = @MASV;

		-- Thông báo thành công
		print 'Sinh viên với MASV = ' + @MASV + ' đã được xóa thành công';
	end try
	begin catch
		declare @ErrorMessage nvarchar(4000) = error_message();
		raiserror(N'Lỗi khi xóa sinh viên: %s', 16, 1, @ErrorMessage);
		return;
	end catch
end
go

-- Nhập điểm cho sinh viên
if exists (select 1 from sys.procedures where name = 'SP_UPD_BANGDIEM')
begin
	drop proc SP_UPD_BANGDIEM
end
go

create proc SP_UPD_BANGDIEM
(
    @MANV varchar(20),
    @MASV varchar(20),
    @MAHP varchar(20),
    @DIEMTHI decimal(4,2)
)
as
begin
    set nocount on;
    
    declare @PUBKEY varchar(20);
    declare @COUNT int;
    declare @MESSAGE nvarchar(200);
    declare @EnGrade varbinary(max);
    
    -- Kiểm tra quyền của nhân viên đối với sinh viên này
    -- (sinh viên phải thuộc lớp do nhân viên quản lý)
    set @COUNT = (
        select count(*) 
        from SINHVIEN SV
        inner join LOP L on SV.MALOP = L.MALOP 
        where L.MANV = @MANV and SV.MASV = @MASV
    );
    
    -- Nếu nhân viên không có quyền quản lý sinh viên này
    if @COUNT = 0
    begin
        set @MESSAGE = 'Nhân viên ' + @MANV + ' không có quyền nhập điểm cho sinh viên ' + @MASV;
        raiserror(@MESSAGE, 16, 1);
        return;
    end;

	-- Kiểm tra nếu asymmetric key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror(N'Khóa RSA không tồn tại', 16, 1);
		return;
	end
    
    -- Mã hóa điểm thi bằng khóa công khai của nhân viên
    set @PUBKEY = (select PUBKEY from NHANVIEN where MANV = @MANV);
	set @EnGrade = encryptbyasymkey(asymkey_id(@PUBKEY), convert(varbinary(max), convert(int, @DIEMTHI * 100)));
    
    -- Kiểm tra xem đã có điểm cho môn học này chưa
    set @COUNT = (
        select count(*) 
        from BANGDIEM 
        where MASV = @MASV and MAHP = @MAHP
    );
    
    -- Nếu chưa có điểm, thêm mới
    if @COUNT = 0
    begin
        insert into BANGDIEM (MASV, MAHP, DIEMTHI)
        values (@MASV, @MAHP, @EnGrade);
        
        set @MESSAGE = 'Đã thêm mới điểm cho sinh viên ' + @MASV + ' môn học ' + @MAHP;
        print @MESSAGE;
    end
    -- Nếu đã có điểm, cập nhật
    else
    begin
        update BANGDIEM
        set DIEMTHI = @EnGrade
        where MASV = @MASV and MAHP = @MAHP;
        
        set @MESSAGE = 'Đã cập nhật điểm cho sinh viên ' + @MASV + ' môn học ' + @MAHP;
        print @MESSAGE;
    end;
    
    -- Trả về danh sách điểm của sinh viên
    select BD.MAHP, HP.TENHP, BD.DIEMTHI
    from BANGDIEM BD
    join HOCPHAN HP on BD.MAHP = HP.MAHP
    where BD.MASV = @MASV;
    
end
go

--drop procedure SP_UPD_BANGDIEM

-- Lấy danh sách điểm của 1 sinh viên
if exists (select 1 from sys.procedures where name = 'SP_SEL_BANGDIEM')
begin
	drop proc SP_SEL_BANGDIEM
end
go

create procedure SP_SEL_BANGDIEM
(
	@MANV varchar(20),
	@MATKHAU nvarchar(32),
	@MASV varchar(20)
)
as
begin
	set nocount on;
	declare @PUBKEY varchar(20);
    declare @COUNT int;

	if @MANV is null
    begin
        raiserror(N'TenDN không tồn tại', 16, 1);
        return;
    end

	select @PUBKEY = PUBKEY from NHANVIEN where @MANV = MANV;

	-- Kiểm tra nếu asymmetric key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror(N'Khóa RSA không tồn tại', 16, 1);
		return;
	end

	declare @OUT nvarchar(max);
	set @COUNT = (
        select count(*) 
        from SINHVIEN 
        inner join LOP on SINHVIEN.MALOP = LOP.MALOP 
        where MANV = @MANV and MASV = @MASV
    );

	if @COUNT = 0
	begin
		raiserror(N'Nhân viên không có quyền xem điểm của sinh viên này', 16, 1);
		return;
	end

	-- Hiển thị điểm đã giải mã
    select BD.MAHP, HP.TENHP, HP.SOTC,
		   convert(decimal(4,2), convert(int, decryptbyasymkey(asymkey_id(@PUBKEY), BD.DIEMTHI, @MATKHAU)) / 100.0) as DIEMTHI
    from BANGDIEM BD
    inner join HOCPHAN HP on BD.MAHP = HP.MAHP
    where BD.MASV = @MASV;
end
go

--drop procedure exec SP_SEL_BANGDIEM  'NV01', '123456', '2112308'

-- Lấy thông tin tất cả lớp do nhân viên quản lý
if exists (select 1 from sys.procedures where name = 'SP_GET_CL')
begin
	drop proc SP_GET_CL
end
go

create proc SP_GET_CL
(
	@MANV varchar(20)
)
as
begin
	select LOP.MALOP, LOP.TENLOP from LOP where LOP.MANV = @MANV
end
go
--drop proc SP_GET_CL

-- Lấy thông tin sinh viên trong một lớp
if exists (select 1 from sys.procedures where name = 'SP_CL_STU')
begin
	drop proc SP_CL_STU
end
go

create proc SP_CL_STU
(
	@MALOP varchar(20),
	@MANV varchar(20)
)
as
begin
	set nocount on;

	-- Kiểm tra đầu vào
    if @MALOP is null or @MANV is null
    begin
        raiserror(N'MALOP hoặc MANV không được để trống', 16, 1);
        return;
    end

    -- Kiểm tra nhân viên có tồn tại
    if not exists (select 1 from NHANVIEN where MANV = @MANV)
    begin
        raiserror(N'MANV không tồn tại', 16, 1);
        return;
    end

    -- Kiểm tra lớp có tồn tại
    if not exists (select 1 from LOP where MALOP = @MALOP)
    begin
        raiserror(N'MALOP không tồn tại', 16, 1);
        return;
    end

    -- Kiểm tra quyền: Nhân viên phải quản lý lớp
    if not exists (
        select 1 
        from LOP 
        where MALOP = @MALOP and MANV = @MANV
    )
    begin
        raiserror(N'Nhân viên không có quyền truy cập thông tin lớp này', 16, 1);
        return;
    end

	-- Truy vấn thông tin sinh viên
    begin try
        select MASV, HOTEN, NGAYSINH, DIACHI, MALOP, TENDN
        from SINHVIEN 
        where MALOP = @MALOP;
    end try
    begin catch
        declare @ErrorMessage nvarchar(4000) = error_message();
        raiserror(N'Lỗi khi truy vấn thông tin sinh viên: %s', 16, 1, @ErrorMessage);
        return;
    end catch
	
end
go

-- exec SP_CL_STU 'CNTT', 'NV01'