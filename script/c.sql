
-- Tạo MASTERKEY
if not exists
(
	select *
	from sys.symmetric_keys
	where symmetric_key_id = 101
)
create master key encryption by
	password = '22120160_22120293_22120299_22120306'
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
		raiserror(N'Các trường dữ liệu cần thiết không được để trống', 16, 1);
		return;
	end

	-- Kiểm tra nếu nhân viên đã tồn tại
	if exists (select 1 from NHANVIEN where MANV = @MANV)
	begin
		raiserror(N'@MANV đã tồn tại', 16, 1);
		return;
	end

	-- Kiểm tra TENDN đã tồn tại
	if exists (select 1 from NHANVIEN where TENDN = @TENDN)
	begin
		raiserror(N'TENDN đã tồn tại', 16, 1);
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
		raiserror(N'TENDN hoặc MK không đúng', 16, 1);
		return;
	end

	-- Kiểm tra nếu Asymmetric Key tồn tại
	if not exists (select 1 from sys.asymmetric_keys where name = @MANV)
	begin
		raiserror(N'Khóa RSA không tồn tại', 16, 1);
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
