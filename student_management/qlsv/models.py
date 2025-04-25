# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class Bangdiem(models.Model):
    masv = models.OneToOneField('Sinhvien', models.DO_NOTHING, db_column='MASV', primary_key=True)  # Field name made lowercase.
    mahp = models.ForeignKey('Hocphan', models.DO_NOTHING, db_column='MAHP')  # Field name made lowercase.
    diemthi = models.BinaryField(db_column='DIEMTHI', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'BANGDIEM'
        unique_together = (('masv', 'mahp'),)


class Hocphan(models.Model):
    mahp = models.CharField(db_column='MAHP', primary_key=True, max_length=20, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    tenhp = models.CharField(db_column='TENHP', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    sotc = models.IntegerField(db_column='SOTC', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'HOCPHAN'


class Lop(models.Model):
    malop = models.CharField(db_column='MALOP', primary_key=True, max_length=20, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    tenlop = models.CharField(db_column='TENLOP', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    manv = models.ForeignKey('Nhanvien', models.DO_NOTHING, db_column='MANV', blank=True, null=True)  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'LOP'
    
    def count(self):
        return self.sinhvien_set.count()


class Nhanvien(models.Model):
    manv = models.CharField(db_column='MANV', primary_key=True, max_length=20, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    hoten = models.CharField(db_column='HOTEN', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    email = models.CharField(db_column='EMAIL', max_length=20, db_collation='Vietnamese_CI_AS', blank=True, null=True)  # Field name made lowercase.
    luong = models.BinaryField(db_column='LUONG', blank=True, null=True)  # Field name made lowercase.
    tendn = models.CharField(db_column='TENDN', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    matkhau = models.BinaryField(db_column='MATKHAU')  # Field name made lowercase.
    pubkey = models.CharField(db_column='PUBKEY', max_length=20, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'NHANVIEN'


class Sinhvien(models.Model):
    masv = models.CharField(db_column='MASV', primary_key=True, max_length=20, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    hoten = models.CharField(db_column='HOTEN', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    ngaysinh = models.DateTimeField(db_column='NGAYSINH', blank=True, null=True)  # Field name made lowercase.
    diachi = models.CharField(db_column='DIACHI', max_length=200, db_collation='Vietnamese_CI_AS', blank=True, null=True)  # Field name made lowercase.
    malop = models.ForeignKey(Lop, models.DO_NOTHING, db_column='MALOP', blank=True, null=True)  # Field name made lowercase.
    tendn = models.CharField(db_column='TENDN', max_length=100, db_collation='Vietnamese_CI_AS')  # Field name made lowercase.
    matkhau = models.BinaryField(db_column='MATKHAU')  # Field name made lowercase.

    class Meta:
        managed = False
        db_table = 'SINHVIEN'


class Sysdiagrams(models.Model):
    name = models.CharField(max_length=128, db_collation='Vietnamese_CI_AS')
    principal_id = models.IntegerField()
    diagram_id = models.AutoField(primary_key=True)
    version = models.IntegerField(blank=True, null=True)
    definition = models.BinaryField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'sysdiagrams'
        unique_together = (('principal_id', 'name'),)
