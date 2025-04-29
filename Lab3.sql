--CAU LENH TAO DB
use master
go
if DB_ID('QLSVNhom') is not null
begin
    alter database QLSVNhom set single_user with rollback immediate;
    drop database QLSVNhom;
end
go

create database QLSVNhom

alter database QLSVNhom
set Compatibility_Level = 120;
go

--CAC CAU LENH TAO TABLE
create table NHANVIEN
(
	MANV varchar(20) not null,
	HOTEN nvarchar(100) not null,
	EMAIL varchar(20),
	LUONG varbinary(max),
	TENDN nvarchar(100) not null,
	MATKHAU varbinary(max) not null,
	PUBKEY varchar(20) not null,
	constraint PK_NV primary key (MANV)
);

create table SINHVIEN
(
	MASV varchar(20) not null,
	HOTEN nvarchar(100) not null,
	NGAYSINH datetime,
	DIACHI nvarchar(200),
	MALOP varchar(20),
	TENDN nvarchar(100) not null,
	MATKHAU varbinary(max) not null,
	constraint PK_SV primary key (MASV)
);

create table LOP
(
	MALOP varchar(20),
	TENLOP nvarchar(100) not null,
	MANV varchar(20),
	constraint PK_L primary key (MALOP)
);

create table HOCPHAN
(
	MAHP varchar(20) not null,
	TENHP nvarchar(100) not null,
	SOTC int,
	constraint PK_HP primary key (MAHP)
);

create table BANGDIEM
(
	MASV varchar(20) not null,
	MAHP varchar(20) not null,
	DIEMTHI varbinary(max),
	constraint PK_BD primary key (MASV, MAHP)
);

 --Quan he
alter table LOP
add constraint FK_L_NV foreign key (MANV) references NHANVIEN (MANV)
on delete cascade
on update cascade;

alter table SINHVIEN 
add constraint FK_SV_L foreign key (MALOP) references LOP (MALOP)
on delete cascade
on update cascade;

alter table BANGDIEM --drop constraint FK_BD_HP
add constraint FK_BD_SV foreign key (MASV) references SINHVIEN (MASV)
on delete cascade
on update cascade;

alter table BANGDIEM
add constraint FK_BD_HP foreign key (MAHP) references HOCPHAN (MAHP)
on delete cascade
on update cascade;

alter table NHANVIEN add constraint UQ_NV_TENDN unique (TENDN);
alter table SINHVIEN add constraint UQ_SV_TENDN unique (TENDN);

--Tao MASTERKEY
if not exists
(
	select *
	from sys.symmetric_keys
	where symmetric_key_id = 101
)
create master key encryption by
	password = '22120306'
go

if not exists
(
	select *
	from sys.certificates
	where name = 'myCert'
)
create certificate myCert
	with subject = 'myCert'
go

--drop master key
--drop certificate myCert	
go
-- Câu c
---- i. Stored dùng để thêm nhân viên: SP_INS_PUBLIC_NHANVIEN
if exists (select 1 from sys.procedures where name = 'SP_INS_PUBLIC_NHANVIEN')
begin
	drop proc SP_INS_PUBLIC_NHANVIEN
end
go

create proc SP_INS_PUBLIC_NHANVIEN 
(
	@MANV varchar(20),
	@HOTEN nvarchar(100),
	@EMAIL varchar(20),
	@LUONGCB int,
	@TENDN nvarchar(100),
	@MK varchar(50)
)
as
begin
	set nocount on;

	-- Kiểm tra các cột bắt buộc
	if @MANV is null or @HOTEN is null or @TENDN is null or @MK is null
	begin
		raiserror('Required fields cannot be NULL', 16, 1);
		return;
	end

	-- Kiểm tra nếu nhân viên đã tồn tại
	if exists (select 1 from NHANVIEN where MANV = @MANV)
	begin
		raiserror('@MANV is exist', 16, 1);
		return;
	end

	-- Kiểm tra TENDN đã tồn tại
	if exists (select 1 from NHANVIEN where TENDN = @TENDN)
	begin
		raiserror('TENDN is exist', 16, 1);
		return;
	end

	declare @PUBKEY varchar(20) = @MANV;

	-- Tạo asymmetric key nếu chưa tồn tại
	if not exists (select * from sys.asymmetric_keys where name = @MANV)
	begin
		exec('create asymmetric key [' + @MANV + '] with algorithm = RSA_512 encryption by password = ''' + @MK + '''');
	end

	-- Băm mật khẩu bằng SHA1
	declare @HashPass varbinary(20);
	set @HashPass = hashbytes('SHA1', @MK);

	-- Mã hóa lương
	declare @EnWage varbinary(max);
	set @EnWage = encryptbyasymkey(asymkey_id(@PUBKEY), cast(@LUONGCB as varchar(20)));

	-- Thêm dữ liệu
	insert into NHANVIEN(MANV, HOTEN, EMAIL, LUONG, TENDN, MATKHAU, PUBKEY)
	values (@MANV, @HOTEN, @EMAIL, @EnWage, @TENDN, @HashPass, @PUBKEY);
end
go


--drop procedure SP_INS_PUBLIC_NHANVIEN

---- ii. Stored dùng để truy vấn dữ liệu nhân viên (NHANVIEN): SP_SEL_PUBLIC_NHANVIEN
if exists (select 1 from sys.procedures where name = 'SP_SEL_PUBLIC_NHANVIEN')
begin
	drop proc SP_SEL_PUBLIC_NHANVIEN
end
go

create proc SP_SEL_PUBLIC_NHANVIEN 
(
	@TENDN nvarchar(100),
	@MK varchar(50)
)
as
begin
	set nocount on;
	declare @PUBKEY varchar(20);

	-- Kiểm tra nhân viên có tồn tại không
	declare @HashPass varbinary(max);
	declare @MANV varchar(20);

	set @HashPass = hashbytes('SHA1', @MK);
	select @MANV = NV.MANV, @PUBKEY = NV.PUBKEY
	from NHANVIEN NV
	where NV.TENDN = @TENDN and NV.MATKHAU = @HashPass;

	if @MANV is null
	begin
		raiserror('Incorrect TENDN or MK', 16, 1);
		return;
	end

	-- Kiểm tra nếu Asymmetric Key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror('RSA key does not exist', 16, 1);
		return;
	end

	-- Giải mã LUONG
	select MANV, HOTEN, EMAIL, 
		convert(int, cast(decryptbyasymkey(asymkey_id(@PUBKEY), LUONG, cast(@MK as nvarchar(50))) as varchar(20))) as LUONGCB 
	from NHANVIEN
	where TENDN = @TENDN;
end
go
	 	 
-- drop procedure SP_SEL_PUBLIC_NHANVIEN
-- exec SP_SEL_PUBLIC_NHANVIEN 'NVA', '123456'

-- Câu d
-- Thêm sinh viên
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
		raiserror('Required fields cannot be NULL', 16, 1);
		return;
	end

	-- Kiểm tra sinh viên đã tồn tại hay chưa
	if exists (select 1 from SINHVIEN where MASV = @MASV)
	begin
		raiserror('@MASV is exist', 16, 1);
		return;
	end

	-- Kiểm tra TENDN đã tồn tại
	if exists (select 1 from SINHVIEN where TENDN = @TENDN)
	begin
		raiserror('TENDN is exist', 16, 1);
		return;
	end

	-- Kiểm tra MALOP tồn tại
	if @MALOP is not null and not exists (select 1 from LOP where MALOP = @MALOP)
	begin
		raiserror('MALOP does not exist', 16, 1);
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
	@MATKHAU varchar(max),
	@ACTION int --1 thêm / 2 xóa / 3 sửa
)
as
begin
	declare @COUNT int;
	set @COUNT = (select count(*) from LOP where MANV = @MANV and MALOP = @MALOP);
    
	if @COUNT = 1
	begin
		if @ACTION = 1
		begin 
			exec SP_INS_SINHVIEN @MASV, @HOTEN, @NGAYSINH, @DIACHI, @MALOP, @TENDN, @MATKHAU;
		end

		if @ACTION = 2
		begin
			delete from SINHVIEN where MASV = @MASV;
		end

		if @ACTION = 3
		begin
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
				set @EnKey = convert(varbinary, hashbytes('MD5', @MATKHAU));
			end

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
		end
	end

	select * from SINHVIEN where MALOP = @MALOP;
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

	-- kiểm tra đầu vào
	if @MASV is null or @MANV is null
	begin
		raiserror('MASV or MANV cannot be NULL', 16, 1);
		return;
	end

	-- kiểm tra nhân viên có tồn tại
	if not exists (select 1 from NHANVIEN where MANV = @MANV)
	begin
		raiserror('MANV does not exist', 16, 1);
		return;
	end

	-- kiểm tra sinh viên có tồn tại
	if not exists (select 1 from SINHVIEN where MASV = @MASV)
	begin
		raiserror('MASV does not exist', 16, 1);
		return;
	end

	-- kiểm tra quyền: nhân viên phải quản lý lớp của sinh viên
	declare @COUNT int;
	set @COUNT = (
		select count(*)
		from SINHVIEN SV
		inner join LOP L on SV.MALOP = L.MALOP
		where SV.MASV = @MASV and L.MANV = @MANV
	);

	if @COUNT = 0
	begin
		raiserror('Nhân viên không có quyền xóa sinh viên này', 16, 1);
		return;
	end

	-- xóa sinh viên
	begin try
		delete from SINHVIEN
		where MASV = @MASV;

		-- thông báo thành công
		print 'Sinh viên với MASV = ' + @MASV + ' đã được xóa thành công';
	end try
	begin catch
		declare @ErrorMessage nvarchar(4000) = error_message();
		raiserror('Lỗi khi xóa sinh viên: %s', 16, 1, @ErrorMessage);
		return;
	end catch
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
    
    -- kiểm tra quyền của nhân viên đối với sinh viên này
    -- (sinh viên phải thuộc lớp do nhân viên quản lý)
    set @COUNT = (
        select count(*) 
        from SINHVIEN SV
        inner join LOP L on SV.MALOP = L.MALOP 
        where L.MANV = @MANV and SV.MASV = @MASV
    );
    
    -- nếu nhân viên không có quyền quản lý sinh viên này
    if @COUNT = 0
    begin
        set @MESSAGE = 'Nhân viên ' + @MANV + ' không có quyền nhập điểm cho sinh viên ' + @MASV;
        raiserror(@MESSAGE, 16, 1);
        return;
    end;

	-- kiểm tra nếu asymmetric key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror('RSA key does not exist', 16, 1);
		return;
	end
    
    -- mã hóa điểm thi bằng khóa công khai của nhân viên
    set @PUBKEY = (select PUBKEY from NHANVIEN where MANV = @MANV);
	set @EnGrade = encryptbyasymkey(asymkey_id(@PUBKEY), convert(varbinary(max), convert(int, @DIEMTHI * 100)));
    
    -- kiểm tra xem đã có điểm cho môn học này chưa
    set @COUNT = (
        select count(*) 
        from BANGDIEM 
        where MASV = @MASV and MAHP = @MAHP
    );
    
    -- nếu chưa có điểm, thêm mới
    if @COUNT = 0
    begin
        insert into BANGDIEM (MASV, MAHP, DIEMTHI)
        values (@MASV, @MAHP, @EnGrade);
        
        set @MESSAGE = 'Đã thêm mới điểm cho sinh viên ' + @MASV + ' môn học ' + @MAHP;
        print @MESSAGE;
    end
    -- nếu đã có điểm, cập nhật
    else
    begin
        update BANGDIEM
        set DIEMTHI = @EnGrade
        where MASV = @MASV and MAHP = @MAHP;
        
        set @MESSAGE = 'Đã cập nhật điểm cho sinh viên ' + @MASV + ' môn học ' + @MAHP;
        print @MESSAGE;
    end;
    
    -- trả về danh sách điểm của sinh viên
    select BD.MAHP, HP.TENHP, BD.DIEMTHI
    from BANGDIEM BD
    join HOCPHAN HP on BD.MAHP = HP.MAHP
    where BD.MASV = @MASV;
    
end
go

--drop procedure SP_UPD_BANGDIEM
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
        raiserror(N'Username does not exist', 16, 1);
        return;
    end

	select @PUBKEY = PUBKEY from NHANVIEN where @MANV = MANV;

	-- kiểm tra nếu asymmetric key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror('RSA key does not exist', 16, 1);
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

	-- hiển thị điểm đã giải mã
    select BD.MAHP, HP.TENHP, HP.SOTC,
		   convert(decimal(4,2), convert(int, decryptbyasymkey(asymkey_id(@PUBKEY), BD.DIEMTHI, @MATKHAU)) / 100.0) as DIEMTHI
    from BANGDIEM BD
    inner join HOCPHAN HP on BD.MAHP = HP.MAHP
    where BD.MASV = @MASV;
end
go

--drop procedure exec SP_SEL_BANGDIEM  'NV01', '123456', '2112308'

-- Lấy thông tin tất cả lớp do nhân viên quản lý
create proc SP_GET_CL
(
	@maNV varchar(20)
)
as
	begin
		select LOP.MALOP, LOP.TENLOP from LOP where LOP.MANV = @maNV
	end
GO
--drop proc SP_GET_CL

-- Lấy thông tin sinh viên trong một lớp
create proc SP_CL_STU
(
	@maLop varchar(20)
)
as
	begin
		select SINHVIEN.MASV, SINHVIEN.HOTEN, SINHVIEN.NGAYSINH, SINHVIEN.DIACHI, SINHVIEN.MALOP, SINHVIEN.TENDN, SINHVIEN.MATKHAU from SINHVIEN where SINHVIEN.MALOP = @maLop
	end
go

--SP cho màn hình đăng nhập
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
        raiserror('Incorret username/id or password', 16, 1);
    end
end
go

--exec SP_LOG_IN 'NVA', '123456'
--HOCPHAN
INSERT INTO DBO.HOCPHAN VALUES('MTH01', N'Phương Pháp Tính', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH02', N'Quy Hoạch Tuyến Tính', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH03', N'Vi Tích Phân 1B', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH04', N'Vi Tích Phân 2B', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH05', N'Đại Số Tuyến Tính', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH06', N'Xác Xuất Thống Kê', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH07', N'Toán Học Tổ Hợp', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH08', N'Toán Học Rời Rạc', 4);
INSERT INTO DBO.HOCPHAN VALUES('MTH09', N'Lý Thuyết Số', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC01', N'Nhập Môn Lập Trình', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC02', N'Cấu Trúc Dữ Liệu Và Giải Thuật', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC03', N'Lập Trình Hướng Đối Tượng', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC04', N'Kĩ Thuật Lập Trình', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC05', N'Mạng Máy Tính', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC06', N'Cơ Sở Dữ Liệu', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC07', N'Hệ Điều Hành', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC08', N'Kiến Trúc Máy Tính Và Hợp Ngữ', 4);
INSERT INTO DBO.HOCPHAN VALUES('CSC09', N'Bảo Mật Cơ Sở Dữ Liệu', 4);
INSERT INTO DBO.HOCPHAN VALUES('BAA01', N'Tư Tưởng Hồ Chí Minh', 2);
INSERT INTO DBO.HOCPHAN VALUES('BAA02', N'Mác Lê Nin', 5);
INSERT INTO DBO.HOCPHAN VALUES('BAA03', N'Đường Lối Của Đảng Cộng Sản Hồ Chí Minh', 2);
GO

--NHANVIEN
--DELETE FROM NHANVIEN WHERE MANV = 'NV01';
EXEC SP_INS_PUBLIC_NHANVIEN 'NV01', N'NGUYEN VAN A', 'nva@yahoo.com', 3000000, N'NVA', '123456'
EXEC SP_INS_PUBLIC_NHANVIEN 'NV02', N'NGUYEN VAN B', 'nvb@yahoo.com', 2000000, N'NVB', '1234567'
exec SP_INS_PUBLIC_NHANVIEN 'NV03', N'Nguyễn Văn C', 'nvc@gmail.com', 5000000, 'NVC', '123456'
EXEC SP_INS_PUBLIC_NHANVIEN 'NV04', N'Nguyễn Văn D', 'nvd@', 3000000, 'nvd', 'abcd12'
GO

--LOP
INSERT INTO LOP VALUES('CNTT', N'Công nghệ thông tin', 'NV01');
INSERT INTO LOP VALUES('CNSH', N'Công nghệ sinh học', 'NV01');
INSERT INTO LOP VALUES('CNHH', N'Công nghệ hóa học', 'NV02');
INSERT INTO LOP VALUES('DTVT', N'Điện tử viễn thông', 'NV03');
GO

--SINHVIEN
EXEC SP_INS_SINHVIEN '22120650', N'Nguyễn Tân Vinh', '2/7/2004', N'Quảng Ngãi', 'CNHH', '22120650', '22120650';
EXEC SP_INS_SINHVIEN '22120662', N'Trà Anh Toàn', '4/15/2004', N'Lạng Sơn', 'CNTT', '22120662', '22120662';
EXEC SP_INS_SINHVIEN '22120208', N'Nguyễn Trần Nhật Minh', '4/13/2004', N'Điện Biên', 'CNSH', '22120208', '22120208';
EXEC SP_INS_SINHVIEN '22120350', N'Nguyễn Văn Hải', '1/9/2003', N'Bến Tre', 'CNSH', '22120350', '22120350';
EXEC SP_INS_SINHVIEN '22120316', N'Phạm Ngọc Điệp', '2/8/2004', N'Sóc Trăng', 'CNTT', '22120316', '22120316';
EXEC SP_INS_SINHVIEN '22120500', N'Lô Thị Mỹ Nương', '7/7/2004', N'Gia Lai', 'CNHH', '22120500', '22120500';
EXEC SP_INS_SINHVIEN '22120327', N'Võ Ngọc Đức', '12/4/2003', N'Vĩnh Long', 'CNSH', '22120327', '22120327';
EXEC SP_INS_SINHVIEN '22120314', N'Ung Tiến Đạt', '7/17/2004', N'Tiền Giang', 'CNTT', '22120314', '22120314';
EXEC SP_INS_SINHVIEN '22120534', N'Hoàng Công Sơn', '2/5/2003', N'Cà Mau', 'CNTT', '22120534', '22120534';
EXEC SP_INS_SINHVIEN '22120547', N'Ngô Nhật Tân', '12/1/2004', N'Lào Cai', 'CNSH', '22120547', '22120547';
EXEC SP_INS_SINHVIEN '22120192', N'Võ Minh Lâm', '6/8/2004', N'Quảng Ninh', 'CNSH', '22120192', '22120192';
EXEC SP_INS_SINHVIEN '22120545', N'Vũ Phan Nhật Tài', '4/24/2003', N'Hải Phòng', 'CNTT', '22120545', '22120545';
EXEC SP_INS_SINHVIEN '22120163', N'Lâm Xương Đức', '6/28/2004', N'Quảng Ngãi', 'CNHH', '22120163', '22120163';
EXEC SP_INS_SINHVIEN '22120047', N'Nguyễn Duy Thiên Kim', '5/22/2004', N'Bắc Kạn', 'CNHH', '22120047', '22120047';
EXEC SP_INS_SINHVIEN '2112493', N'Nguyễn Hoàng Huy', '11/10/2003', N'Nam Định', 'CNSH', '2112493', '2112493';
EXEC SP_INS_SINHVIEN '2112468', N'Võ Công Huân', '6/8/2004', N'Hà Tĩnh', 'CNTT', '2112468', '2112468';
EXEC SP_INS_SINHVIEN '22120447', N'Lê Hoàng Long', '7/5/2003', N'Lào Cai', 'CNHH', '22120447', '22120447';
EXEC SP_INS_SINHVIEN '22120399', N'Phạm Đức Huy', '4/10/2003', N'Vĩnh Phúc', 'CNHH', '22120399', '22120399';
EXEC SP_INS_SINHVIEN '22120414', N'Lâm Ngọc Anh Khoa', '1/20/2004', N'Bắc Kạn', 'CNSH', '22120414', '22120414';
EXEC SP_INS_SINHVIEN '22120422', N'Trần Thái Đăng Khoa', '12/20/2003', N'Nam Định', 'CNHH', '22120422', '22120422';
EXEC SP_INS_SINHVIEN '22120552', N'Võ Minh Tân', '2/10/2003', N'Bà Rịa - Vũng Tàu', 'CNTT', '22120552', '22120552';
EXEC SP_INS_SINHVIEN '22120554', N'Nguyễn Quốc Thái', '10/8/2003', N'Thái Bình', 'CNHH', '22120554', '22120554';
EXEC SP_INS_SINHVIEN '22120556', N'Hồng Minh Thắng', '10/10/2003', N'Đồng Tháp', 'CNTT', '22120556', '22120556';
EXEC SP_INS_SINHVIEN '22120387', N'Trần Hữu Hoàng', '4/26/2003', N'Bắc Ninh', 'CNTT', '22120387', '22120387';
EXEC SP_INS_SINHVIEN '22120418', N'Phạm Minh Khoa', '11/13/2003', N'Đà Nẵng', 'CNTT', '22120418', '22120418';
EXEC SP_INS_SINHVIEN '22120383', N'Huỳnh Ngọc Hoà', '11/6/2004', N'Đồng Nai', 'CNTT', '22120383', '22120383';
EXEC SP_INS_SINHVIEN '22120518', N'Phạm Thị Bích Phượng', '3/24/2004', N'Bắc Ninh', 'CNTT', '22120518', '22120518';
EXEC SP_INS_SINHVIEN '22120538', N'Võ Nguyễn Hồng Sơn', '11/18/2003', N'Kiên Giang', 'CNSH', '22120538', '22120538';
EXEC SP_INS_SINHVIEN '22120580', N'Đinh Quang Thọ', '5/27/2003', N'Thừa Thiên Huế', 'CNSH', '22120580', '22120580';
EXEC SP_INS_SINHVIEN '22120583', N'Trương Quốc Thuận', '2/5/2004', N'Tây Ninh', 'CNTT', '22120583', '22120583';
EXEC SP_INS_SINHVIEN '22120605', N'Hoàng Thị Thùy Trang', '9/7/2004', N'Quảng Ninh', 'CNSH', '22120605', '22120605';
EXEC SP_INS_SINHVIEN '22120632', N'Lê Nhật Tuấn', '5/24/2004', N'Hà Tĩnh', 'CNSH', '22120632', '22120632';
EXEC SP_INS_SINHVIEN '22120444', N'Dương Thành Long', '4/9/2003', N'Phú Yên', 'CNSH', '22120444', '22120444';
EXEC SP_INS_SINHVIEN '22120490', N'Lăng Văn Nhàn', '4/4/2004', N'Kon Tum', 'CNSH', '22120490', '22120490';
EXEC SP_INS_SINHVIEN '22120501', N'Nguyễn Thành Phát', '2/18/2004', N'Kiên Giang', 'CNHH', '22120501', '22120501';
EXEC SP_INS_SINHVIEN '22120287', N'Phan Xuân Bảo', '6/18/2004', N'Bình Phước', 'CNSH', '22120287', '22120287';
EXEC SP_INS_SINHVIEN '22120631', N'Lê Nguyên Tuấn', '11/18/2004', N'Lào Cai', 'CNHH', '22120631', '22120631';
EXEC SP_INS_SINHVIEN '2112894', N'Đặng Thị Thúy Uyên', '10/28/2003', N'Hà Giang', 'CNTT', '2112894', '2112894';
EXEC SP_INS_SINHVIEN '22120241', N'Trần Quốc Thịnh', '1/2/2004', N'Sóc Trăng', 'CNHH', '22120241', '22120241';
EXEC SP_INS_SINHVIEN '22120302', N'Phạm Hải Đăng', '12/15/2003', N'Đà Nẵng', 'CNTT', '22120302', '22120302';
EXEC SP_INS_SINHVIEN '22120303', N'Phan Khắc Thành Danh', '9/13/2004', N'Đắk Nông', 'CNTT', '22120303', '22120303';
EXEC SP_INS_SINHVIEN '22120247', N'Phạm Hồ Ngọc Trâm', '6/18/2003', N'Trà Vinh', 'CNSH', '22120247', '22120247';
EXEC SP_INS_SINHVIEN '22120261', N'Phạm Hoàng Việt', '11/10/2003', N'Bạc Liêu', 'CNTT', '22120261', '22120261';
EXEC SP_INS_SINHVIEN '22120213', N'Võ Đại Nam', '10/7/2004', N'Hải Dương', 'CNHH', '22120213', '22120213';
EXEC SP_INS_SINHVIEN '22120158', N'Lý Ngọc Bình', '1/3/2004', N'Sóc Trăng', 'CNTT', '22120158', '22120158';
EXEC SP_INS_SINHVIEN '22120169', N'Nguyễn Thùy Dương', '8/8/2004', N'Đắk Nông', 'CNHH', '22120169', '22120169';
EXEC SP_INS_SINHVIEN '22120175', N'Nguyễn Vũ Hà', '4/22/2004', N'Phú Thọ', 'CNSH', '22120175', '22120175';
EXEC SP_INS_SINHVIEN '22120358', N'Nguyễn Văn Hảo', '8/12/2004', N'Khánh Hòa', 'CNTT', '22120358', '22120358';
EXEC SP_INS_SINHVIEN '22120367', N'Trần Nhật Hiệp', '12/18/2003', N'Tiền Giang', 'CNSH', '22120367', '22120367';
EXEC SP_INS_SINHVIEN '22120370', N'Đinh Thị Minh Hiếu', '2/23/2003', N'Bình Dương', 'CNHH', '22120370', '22120370';
EXEC SP_INS_SINHVIEN '22120553', N'Nguyễn Lê Ngọc Tần', '1/2/2004', N'Hà Nội', 'CNTT', '22120553', '22120553';
EXEC SP_INS_SINHVIEN '22120614', N'Nguyễn Văn Trị', '11/24/2004', N'TP HCM', 'CNSH', '22120614', '22120614';
EXEC SP_INS_SINHVIEN '22120448', N'Nguyễn Đại Long', '11/28/2003', N'Đà Nẵng', 'CNTT', '22120448', '22120448';
EXEC SP_INS_SINHVIEN '22120334', N'Nguyễn Trí Dũng', '12/24/2004', N'Long An', 'CNTT', '22120334', '22120334';
EXEC SP_INS_SINHVIEN '22120349', N'Nguyễn Thanh Hải', '9/2/2003', N'Vĩnh Phúc', 'CNSH', '22120349', '22120349';
EXEC SP_INS_SINHVIEN '22120366', N'Nguyễn Văn Hiệp', '7/19/2004', N'Quảng Ninh', 'CNHH', '22120366', '22120366';
EXEC SP_INS_SINHVIEN '22120102', N'Nguyễn Ích Tú', '8/24/2004', N'Hà Giang', 'CNHH', '22120102', '22120102';
EXEC SP_INS_SINHVIEN '22120603', N'Lý Quỳnh Trâm', '8/16/2004', N'Vĩnh Phúc', 'CNHH', '22120603', '22120603';
EXEC SP_INS_SINHVIEN '22120646', N'Trần Thị Vi', '7/7/2004', N'Sơn La', 'CNTT', '22120646', '22120646';
EXEC SP_INS_SINHVIEN '22120396', N'Ngô Quang Huy', '7/23/2004', N'Phú Yên', 'CNSH', '22120396', '22120396';
EXEC SP_INS_SINHVIEN '22120397', N'Nguyễn Đặng Hồng Huy', '8/24/2003', N'Hải Dương', 'CNHH', '22120397', '22120397';
EXEC SP_INS_SINHVIEN '22120401', N'Mai Khánh Huyền', '4/7/2004', N'Hà Giang', 'CNHH', '22120401', '22120401';
EXEC SP_INS_SINHVIEN '22120606', N'Trần Thị Trang', '12/18/2004', N'Bình Thuận', 'CNHH', '22120606', '22120606';
EXEC SP_INS_SINHVIEN '22120609', N'Hồ Khắc Minh Trí', '11/20/2004', N'Hậu Giang', 'CNSH', '22120609', '22120609';
EXEC SP_INS_SINHVIEN '22120634', N'Nguyễn Lê Anh Tuấn', '8/14/2003', N'Hải Phòng', 'CNHH', '22120634', '22120634';
EXEC SP_INS_SINHVIEN '22120469', N'Nguyễn Hoài Nam', '7/17/2004', N'Tuyên Quang', 'CNTT', '22120469', '22120469';
EXEC SP_INS_SINHVIEN '22120510', N'Cao Xuân Hồng Phúc', '2/22/2004', N'Sơn La', 'CNTT', '22120510', '22120510';
EXEC SP_INS_SINHVIEN '22120227', N'Phạm Văn Minh Phương', '7/21/2004', N'Đà Nẵng', 'CNHH', '22120227', '22120227';
EXEC SP_INS_SINHVIEN '22120435', N'Nguyễn Chí Lập', '7/18/2003', N'Bà Rịa - Vũng Tàu', 'CNTT', '22120435', '22120435';
EXEC SP_INS_SINHVIEN '22120378', N'Trần Văn Hiếu', '11/9/2003', N'Cần Thơ', 'CNHH', '22120378', '22120378';
EXEC SP_INS_SINHVIEN '22120446', N'HUỲNH HOÀNG LONG', '4/15/2004', N'Vĩnh Long', 'CNSH', '22120446', '22120446';
EXEC SP_INS_SINHVIEN '22120196', N'Nguyễn Đình Lộc', '6/19/2003', N'Hà Nội', 'CNSH', '22120196', '22120196';
EXEC SP_INS_SINHVIEN '22120306', N'Lê Thọ Đạt', '4/12/2003', N'Gia Lai', 'CNSH', '22120306', '22120306';
EXEC SP_INS_SINHVIEN '22120641', N'Nguyễn Bách Tùng', '8/9/2004', N'Cà Mau', 'CNSH', '22120641', '22120641';
EXEC SP_INS_SINHVIEN '22120273', N'Phạm Hoàng An', '9/17/2004', N'Nghệ An', 'CNHH', '22120273', '22120273';
EXEC SP_INS_SINHVIEN '22120237', N'Bạch Tăng Thắng', '1/16/2004', N'Bình Định', 'CNSH', '22120237', '22120237';
EXEC SP_INS_SINHVIEN '22120299', N'Trương Công Quốc Cường', '5/28/2003', N'Quảng Ninh', 'CNSH', '22120299', '22120299';
EXEC SP_INS_SINHVIEN '22120214', N'Lê Ngọc Bảo Ngân', '3/9/2003', N'Hòa Bình', 'CNHH', '22120214', '22120214';
EXEC SP_INS_SINHVIEN '22120215', N'Vũ Yến Ngọc', '5/19/2003', N'Vĩnh Phúc', 'CNHH', '22120215', '22120215';
EXEC SP_INS_SINHVIEN '22120456', N'Lại Bùi Thành Luân', '2/21/2003', N'Quảng Ninh', 'CNSH', '22120456', '22120456';
EXEC SP_INS_SINHVIEN '22120645', N'Bùi Thanh Uy', '3/21/2003', N'Tây Ninh', 'CNHH', '22120645', '22120645';
EXEC SP_INS_SINHVIEN '22120557', N'Võ Đức Thắng', '9/12/2004', N'Bình Thuận', 'CNHH', '22120557', '22120557';
EXEC SP_INS_SINHVIEN '22120627', N'Lê Huỳnh Quang Trường', '2/15/2004', N'Khánh Hòa', 'CNSH', '22120627', '22120627';
EXEC SP_INS_SINHVIEN '2112373', N'Huỳnh Nhật Dương', '12/2/2003', N'Bình Thuận', 'CNTT', '2112373', '2112373';
EXEC SP_INS_SINHVIEN '2112308', N'Nguyễn Chí Cường', '5/4/2003', N'Hà Tĩnh', 'CNTT', '2112308', '2112308';
EXEC SP_INS_SINHVIEN '2112362', N'Trịnh Cao Văn Đức', '5/10/2003', N'Kiên Giang', 'CNSH', '2112362', '2112362';
EXEC SP_INS_SINHVIEN '2112935', N'PHOMMALA SISOUVANH', '3/9/2003', N'Tuyên Quang', 'CNSH', '2112935', '2112935';
EXEC SP_INS_SINHVIEN '22120637', N'Ừng Văn Tuấn', '12/21/2004', N'Bạc Liêu', 'CNSH', '22120637', '22120637';
EXEC SP_INS_SINHVIEN '22120657', N'Trình Xuân Vỹ', '12/9/2004', N'Hòa Bình', 'CNTT', '22120657', '22120657';
EXEC SP_INS_SINHVIEN '22120577', N'Nguyễn Phúc Hưng Thịnh', '12/8/2003', N'Quảng Ninh', 'CNHH', '22120577', '22120577';
EXEC SP_INS_SINHVIEN '22120642', N'Tống Sơn Tùng', '7/20/2003', N'Kon Tum', 'CNSH', '22120642', '22120642';
EXEC SP_INS_SINHVIEN '2112781', N'Trần Vương Thiên', '1/26/2003', N'Bắc Kạn', 'CNSH', '2112781', '2112781';
EXEC SP_INS_SINHVIEN '22120400', N'Trần Minh Huy', '5/16/2003', N'An Giang', 'CNSH', '22120400', '22120400';
EXEC SP_INS_SINHVIEN '22120560', N'Lê Hữu Thanh', '4/20/2004', N'Lào Cai', 'CNSH', '22120560', '22120560';
EXEC SP_INS_SINHVIEN '22120570', N'Nguyễn Thanh Thi', '8/17/2003', N'Bạc Liêu', 'CNTT', '22120570', '22120570';
EXEC SP_INS_SINHVIEN '22120590', N'Lê Việt Tiến', '10/13/2004', N'Sơn La', 'CNTT', '22120590', '22120590';
EXEC SP_INS_SINHVIEN '22120513', N'Nguyễn Hoàng Đức Phúc', '11/16/2004', N'Hà Nam', 'CNHH', '22120513', '22120513';
EXEC SP_INS_SINHVIEN '22120635', N'Nguyễn Xuân Tuấn', '7/14/2003', N'Thái Nguyên', 'CNTT', '22120635', '22120635';
EXEC SP_INS_SINHVIEN '22120636', N'Trần Ngọc Tuấn', '1/4/2004', N'Kon Tum', 'CNSH', '22120636', '22120636';
EXEC SP_INS_SINHVIEN '22120254', N'Nguyễn Huy Tú', '2/19/2003', N'Yên Bái', 'CNSH', '22120254', '22120254';
EXEC SP_INS_SINHVIEN '22120035', N'Đoàn Nguyễn Tấn Hưng', '9/18/2004', N'Bình Dương', 'CNSH', '22120035', '22120035';
EXEC SP_INS_SINHVIEN '22120263', N'Nguyễn Quang Vinh', '9/25/2003', N'Đắk Nông', 'CNHH', '22120263', '22120263';
EXEC SP_INS_SINHVIEN '22120154', N'Võ Thiện An', '7/26/2003', N'Yên Bái', 'CNTT', '22120154', '22120154';
EXEC SP_INS_SINHVIEN '22120180', N'Võ Xuân Hoà', '4/22/2004', N'Phú Yên', 'CNHH', '22120180', '22120180';
EXEC SP_INS_SINHVIEN '22120072', N'Phạm Lê Hoài Phương', '3/25/2003', N'Bắc Ninh', 'CNSH', '22120072', '22120072';
EXEC SP_INS_SINHVIEN '22120098', N'Hoàng Trần Thành Trung', '8/11/2004', N'Phú Thọ', 'CNTT', '22120098', '22120098';
EXEC SP_INS_SINHVIEN '22120176', N'Văn Trọng Hân', '9/21/2004', N'Sơn La', 'CNSH', '22120176', '22120176';
EXEC SP_INS_SINHVIEN '1612647', N'Lê Văn Thi', '1/11/2003', N'Tây Ninh', 'CNHH', '1612647', '1612647';
EXEC SP_INS_SINHVIEN '22120217', N'Nguyễn Trần Ái Nguyên', '1/4/2003', N'Điện Biên', 'CNHH', '22120217', '22120217';
EXEC SP_INS_SINHVIEN '22120437', N'Ngô Thị Thùy Linh', '10/19/2003', N'Đà Nẵng', 'CNHH', '22120437', '22120437';
EXEC SP_INS_SINHVIEN '22120281', N'Ksor Âu', '4/25/2003', N'An Giang', 'CNSH', '22120281', '22120281';
EXEC SP_INS_SINHVIEN '22120065', N'Đinh Nguyễn Tấn Nguyên', '11/8/2003', N'TP HCM', 'CNSH', '22120065', '22120065';
EXEC SP_INS_SINHVIEN '2112779', N'Trương Thị Thu Thảo', '4/23/2004', N'Nam Định', 'CNSH', '2112779', '2112779';
GO

GO
--BANGDIEM
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120650', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120662', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120208', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120350', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120316', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120500', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120327', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120314', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120534', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120547', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120192', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120545', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120163', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120047', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112493', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112468', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120447', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120399', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120414', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120422', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120552', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120554', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120556', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120387', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120418', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120383', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120518', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120538', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120580', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120583', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120605', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120632', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120444', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120490', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120501', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120287', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120631', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112894', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120241', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120302', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120303', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120247', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120261', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120213', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120158', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120169', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120175', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120358', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120367', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120370', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120553', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120614', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120448', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120334', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120349', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120366', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120102', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120603', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120646', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120396', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120397', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120401', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120606', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120609', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120634', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120469', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120510', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120227', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120435', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120378', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120446', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120196', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120306', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120641', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120273', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120237', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120299', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120214', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120215', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120456', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120645', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120557', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120627', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112373', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112308', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112362', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112935', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120637', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120657', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120577', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120642', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112781', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120400', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120560', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120570', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120590', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120513', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120635', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120636', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120254', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120035', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120263', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120154', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120180', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120072', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120098', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120176', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('1612647', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120217', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120437', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120281', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('22120065', 'BAA03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'MTH09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC03', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC04', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC05', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC06', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC07', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC08', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'CSC09', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'BAA01', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'BAA02', NULL);
INSERT INTO DBO.BANGDIEM VALUES('2112779', 'BAA03', NULL);
GO