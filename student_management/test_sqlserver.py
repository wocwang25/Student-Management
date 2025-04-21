import pyodbc

try:
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=localhost;'
        'DATABASE=master;'
        'UID=yusato;'
        'PWD=lolicute;'
    )
    print("Kết nối SQL Server thành công!")
    conn.close()
except Exception as e:
    print(f"Lỗi kết nối SQL Server: {e}")