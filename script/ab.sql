-- Câu lệnh tạo Database
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

-- Các câu lệnh tạo table
use QLSVNhom
go

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

-- Quan hệ
alter table LOP
add constraint FK_L_NV foreign key (MANV) references NHANVIEN (MANV)
on delete cascade
on update cascade;

alter table SINHVIEN 
add constraint FK_SV_L foreign key (MALOP) references LOP (MALOP)
on delete cascade
on update cascade;

alter table BANGDIEM
add constraint FK_BD_SV foreign key (MASV) references SINHVIEN (MASV)
on delete cascade
on update cascade;

alter table BANGDIEM
add constraint FK_BD_HP foreign key (MAHP) references HOCPHAN (MAHP)
on delete cascade
on update cascade;

alter table NHANVIEN add constraint UQ_NV_TENDN unique (TENDN);
alter table SINHVIEN add constraint UQ_SV_TENDN unique (TENDN);