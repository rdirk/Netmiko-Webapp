from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    send_from_directory, 
    send_file, 
    abort, 
    flash, 
    session, 
    make_response, 
    jsonify
)
from flask_session import Session
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from werkzeug.utils import safe_join
from backup_config import backup_konfigurasi, perangkat
import logging
import os
import zipfile
import datetime as dt
from io import BytesIO
from functools import wraps
import io
import sys
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import pandas as pd
from config.dbconfig import MYSQL_CONFIG 
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from datetime import timedelta
import mysql.connector
from mysql.connector import Error, connect
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta

FolderPath = r'backup'


app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'KvBRVpO3ltFH0WLTaO38WA'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "flask_session"
# Konfigurasi MySQL
app.config.update(MYSQL_CONFIG)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

Session(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Login Required."
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"
login_manager.remember_cookie_duration = timedelta(minutes=10)

app.permanent_session_lifetime = timedelta(minutes=10)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Konfigurasi MySQL
db_config = {
    'user': MYSQL_CONFIG['MYSQL_USER'],
    'password': MYSQL_CONFIG['MYSQL_PASSWORD'],
    'host': MYSQL_CONFIG['MYSQL_HOST'],
    'database': MYSQL_CONFIG['MYSQL_DB']
}

def get_db_connection():
    try:
        connec = mysql.connector.connect(**db_config)
        if connec.is_connected():
            return connec
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            if user and bcrypt.check_password_hash(user['password'], password_input):
                user_obj = User(user['id'])
                login_user(user_obj)
                session['username'] = user['username']
                flash('Login Success', 'success')
                return redirect(url_for('base'))
            else:
                flash('Login Error. Check your username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    flash('Logout berhasil.', 'success')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def base():
    if 'username' in session:
        username = session['username']
        return render_template('base.html', username=username)  # Pastikan Anda memiliki file base.html di dalam folder templates
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        return render_template('base.html', username=username)
    return 'Your not login <a href="/login">Login here</a>'

def getReadableByteSize(num, suffix='B') -> str:
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Y', suffix)

def getTimeStampString(tSec: float) -> str:
    tObj = dt.datetime.fromtimestamp(tSec)
    tStr = dt.datetime.strftime(tObj, '%Y-%m-%d %H:%M:%S')
    return tStr

def getIconClassForFilename(fName):
    fileExt = Path(fName).suffix
    fileExt = fileExt[1:] if fileExt.startswith(".") else fileExt
    fileTypes = ["aac", "ai", "bmp", "cs", "css", "csv", "doc", "docx", "exe", "gif", "heic", "html", "java", "jpg", "js", "json", "jsx", "key", "m4p", "md", "mdx", "mov", "mp3",
                 "mp4", "otf", "pdf", "php", "png", "pptx", "psd", "py", "raw", "rb", "sass", "scss", "sh", "sql", "svg", "tiff", "tsx", "ttf", "txt", "wav", "woff", "xlsx", "xml", "yml"]
    fileIconClass = f"bi bi-filetype-{fileExt}" if fileExt in fileTypes else "bi bi-file-earmark"
    return fileIconClass

# route handler
@app.route('/reports/', defaults={'reqPath': ''})
@app.route('/reports/<path:reqPath>')
@login_required
def getFiles(reqPath):
    
    # Join the base and the requested path
    # could have done os.path.join, but safe_join ensures that files are not fetched from parent folders of the base folder
    absPath = safe_join(FolderPath, reqPath)

    # Return 404 if path doesn't exist
    if not os.path.exists(absPath):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(absPath):
        return send_file(absPath)

    # Show directory contents
    def fObjFromScan(x):
        fileStat = x.stat()
        # return file information for rendering
        return {'name': x.name,
                'fIcon': "bi bi-folder-fill" if os.path.isdir(x.path) else getIconClassForFilename(x.name),
                'relPath': os.path.relpath(x.path, FolderPath).replace("\\", "/"),
                'mTime': getTimeStampString(fileStat.st_mtime),
                'size': getReadableByteSize(fileStat.st_size),
                'isDir': os.path.isdir(x.path)}  # Added 'isDir' to indicate if the object is a directory
    fileObjs = [fObjFromScan(x) for x in os.scandir(absPath)]
    # get parent directory url
    parentFolderPath = os.path.relpath(
        Path(absPath).parents[0], FolderPath).replace("\\", "/")
    if 'username' in session:
        username = session['username']
        return render_template('daftar.html', data={'files': fileObjs,
                                                 'parentFolder': parentFolderPath}, username=username)  # Pastikan Anda memiliki file base.html di dalam folder templates
    return redirect(url_for('login'))
    # return render_template('daftar.html', data={'files': fileObjs,
    #                                              'parentFolder': parentFolderPath})
def reports():
    if 'username' in session:
        username = session['username']
        return render_template('base.html', username=username)  # Pastikan Anda memiliki file base.html di dalam folder templates
    return redirect(url_for('login'))
@app.route('/backup-config')
@login_required
def backup_config():
    if 'username' in session:
        username = session['username']
        return render_template('backup_config.html', username=username)  # Pastikan Anda memiliki file base.html di dalam folder templates
    return redirect(url_for('login'))
    # return render_template('backup_config.html')

@app.route('/download-zip', methods=['GET','POST'])
@login_required
def download_zip():
    reqPath = request.args.get('reqPath', '')  # Mendapatkan reqPath dari parameter query
    zip_name = f'{reqPath}.zip'
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(os.path.join(FolderPath, reqPath)):
            for file in files:
                file_path = os.path.join(root, file)
                zip_file.write(file_path, os.path.relpath(file_path, os.path.join(FolderPath, reqPath)))

    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=zip_name, mimetype='application/zip')
def create_zip_from_directory(directory_path, zip_name):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                zip_file.write(file_path, os.path.relpath(file_path, directory_path))
    zip_buffer.seek(0)
    return zip_buffer

@app.route('/download-reports-zip')
@login_required
def download_reports_zip():
    zip_name = 'all.zip'
    # Membuat ZIP dari seluruh direktori laporan
    zip_buffer = create_zip_from_directory(FolderPath, zip_name)
    
    # Mengirim file ZIP sebagai respons
    return send_file(zip_buffer, as_attachment=True, download_name=zip_name, mimetype='application/zip')

@app.route('/trigger-backup')
@login_required
def trigger_backup():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        
        # Ambil data perangkat terbaru dari database
        query = """
        SELECT perangkat.device_type, perangkat.ip, perangkat.username, perangkat.password, perangkat.location, commands.command
        FROM perangkat
        JOIN commands ON perangkat.device_type = commands.device_type
        """
        cursor.execute(query)
        perangkat = [
            {
                'device_type': row['device_type'],
                'host': row['ip'],
                'username': row['username'],
                'password': row['password'],
                'port': 22,
                'command': row['command'],
                'location': row['location']
            }
            for row in cursor.fetchall()
        ]
        cursor.close()
        connection.close()

        # Menyimpan referensi ke stdout asli
        original_stdout = sys.stdout
        
        # Membuat objek StringIO untuk menangkap output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        try:
            logging.info('Backup start at: %s', dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(backup_konfigurasi, [p]) for p in perangkat]
                for future in futures:
                    future.result(timeout=360)
        except TimeoutError:
            flash('Timeout', 'warning')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

        # Mengembalikan stdout ke aslinya
        sys.stdout = original_stdout
        
        # Mendapatkan isi output yang ditangkap
        output = captured_output.getvalue()
        
        # Menutup objek StringIO
        captured_output.close()

        if 'username' in session:
            username = session['username']
            return render_template('backup_config.html', username=username, output=output)
    return redirect(url_for('login'))

@app.route('/info')
@login_required
def info():
    if 'username' in session:
        username = session['username']
        return render_template('info.html', username=username)  # Pastikan Anda memiliki file base.html di dalam folder templates
    return redirect(url_for('login'))

@app.route('/view-device')
@login_required
def view_perangkat():
    page = request.args.get('page', 1, type=int)
    perpage = 5
    startat = (page - 1) * perpage
    search_query = request.args.get('search', '')

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        if search_query:
            search_like = f"%{search_query}%"
            cursor.execute('SELECT * FROM perangkat WHERE id LIKE %s OR hostname LIKE %s OR ip LIKE %s LIMIT %s, %s;', 
                           (search_like, search_like, search_like, startat, perpage))
        else:
            cursor.execute('SELECT * FROM perangkat LIMIT %s, %s;', (startat, perpage))

        data = list(cursor.fetchall())

        # Menghitung total halaman dengan atau tanpa pencarian
        if search_query:
            cursor.execute('SELECT COUNT(*) FROM perangkat WHERE id LIKE %s OR hostname LIKE %s OR ip LIKE %s', (search_like, search_like, search_like))
        else:
            cursor.execute('SELECT COUNT(*) FROM perangkat')
        total = cursor.fetchone()
        total_pages = total['COUNT(*)'] // perpage + (total['COUNT(*)'] % perpage > 0)

        # Logika pagination
        left_window = max(1, page - 2)
        right_window = min(total_pages, page + 2)
        
        cursor.close()
        connection.close()

    if 'username' in session:
        username = session['username']
        return render_template('view_device.html', perangkat=data, username=username, page=page, total_pages=total_pages, left_window=left_window, right_window=right_window, search_query=search_query)
    return redirect(url_for('login'))

@app.route('/upload-excel', methods=['POST', 'GET'])
@login_required
def upload_excel():
    if request.method == 'POST':
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            if 'file' not in request.files:
                flash('Tidak ada file bagian', 'danger')
                return redirect(request.url)
            file = request.files['file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'danger')
        return redirect(request.url)
    if file and file.filename.endswith('.xlsx'):
        try:
            df = pd.read_excel(file)
            cursor = connection.cursor()
            for index, row in df.iterrows():
                cursor.execute("INSERT INTO perangkat (device_type, hostname, ip, location, username, password) VALUES (%s, %s, %s, %s, %s, %s)", 
                               (row['device_type'], row['hostname'], row['ip'], row['location'], row['username'], row['password']))
            connection.commit()
            cursor.close()
            flash('Import Success', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    else:
        flash('Invalid Format', 'danger')
    return redirect(url_for('view_perangkat'))

@app.route('/export-excel')
@login_required
def export_excel():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM perangkat"
        cursor.execute(query)
        result = cursor.fetchall()
        cursor.close()
        connection.close()

    # Konversi hasil query ke DataFrame pandas
    df = pd.DataFrame(result)

    # Tentukan nama file Excel yang akan dihasilkan
    excel_file = BytesIO()
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Perangkat', index=False)

    excel_file.seek(0)

    # Membuat response
    response = make_response(excel_file.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = 'attachment; filename=Daftar_Perangkat.xlsx'

    return response

@app.route('/hapus-perangkat/<int:id>', methods=['GET'])
@login_required
def hapus_perangkat(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("DELETE FROM perangkat WHERE id = %s", (id,))
            connection.commit()
            cursor.close()
            flash('Delete Success', 'success')
        except Exception as e:
            flash('Error Delete Device: ' + str(e), 'danger')
        cursor.close()
        connection.close()
    return redirect(url_for('view_perangkat'))

@app.route('/edit-perangkat/<int:id>', methods=['GET'])
@login_required
def edit_perangkat(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM perangkat WHERE id = %s", (id,))
        perangkat = cursor.fetchone()
        cursor.close()

    if perangkat:
        device_type = get_device_types()
        if 'username' in session:
            username = session['username']
            return render_template('edit_perangkat.html', perangkat=perangkat, username=username, commands=device_type)
    flash('Device Not Found', 'danger')
    return redirect(url_for('login'))

@app.route('/update-perangkat', methods=['POST'])
@login_required
def update_perangkat():
    id = request.form['id']
    hostname = request.form['hostname']
    location = request.form['location']
    ip = request.form['ip']
    username = request.form['username']
    password = request.form['password']
    type = request.form['type']
    
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            # Memperbarui data di database termasuk username dan password
            cursor.execute(
                "UPDATE perangkat SET device_type=%s, ip=%s, location=%s, hostname=%s, username=%s, password=%s WHERE id=%s",
                (type, ip, location, hostname, username, password, id)
            )
            connection.commit()
            flash('Update Success', 'success')
        except Exception as e:
            flash(f'Update error {str(e)}', 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('view_perangkat'))

@app.route('/tambah-perangkat', methods=['GET'])
@login_required
def form_tambah_perangkat():
    if 'username' in session:
        username = session['username']
        device_types = get_device_types()  # Ambil device types dari database
        return render_template('add_device.html', username=username, commands=device_types)
    return redirect(url_for('login'))

@app.route('/tambah-perangkat', methods=['POST'])
@login_required
def tambah_perangkat():
    # base_nama = request.form['nama']
    hostname = request.form['hostname']
    location = request.form['location']
    ip = request.form['ip']
    username = request.form['username']  # Menambahkan input username
    password = request.form['password']  # Menambahkan input password
    type = request.form['type']
    
    # Menghitung jumlah entri untuk jenis perangkat yang dipilih
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT COUNT(*) FROM perangkat WHERE hostname LIKE %s"
        like_pattern = f"{hostname}%"
        cursor.execute(query, (like_pattern,))
        result = cursor.fetchone()

        if result is None:
            jumlah = 0
        else:
            jumlah = result['COUNT(*)']

        # nama = f"{base_nama}_{jumlah + 1}"
        
        # Menambahkan data ke database termasuk username dan password
        cursor.execute("INSERT INTO perangkat (device_type, hostname, ip, location, username, password) VALUES (%s, %s, %s, %s, %s, %s)", (type, hostname, ip, location, username, password))
        connection.commit()
        cursor.close()
        flash('Add Success', 'success')
    return redirect(url_for('view_perangkat'))

@app.route('/edit-password', methods=['GET', 'POST'])
@login_required
def edit_password():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        username = session['username']

        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], old_password):
            new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            cursor.execute('UPDATE users SET password = %s WHERE username = %s', (new_password_hash, username))
            connection.commit()
            flash('Change Password Success', 'success')
            return redirect(url_for('base'))
        else:
            flash('Old Password not match', 'danger')

    return render_template('edit_password.html')

@app.route('/view-type')
@login_required
def view_type():
    page = request.args.get('page', 1, type=int)
    perpage = 5
    startat = (page - 1) * perpage
    search_query = request.args.get('search', '')

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        if search_query:
            search_like = f"%{search_query}%"
            cursor.execute('SELECT * FROM commands WHERE id LIKE %s OR device_type LIKE %s OR command LIKE %s LIMIT %s, %s;', 
                           (search_like, search_like, search_like, startat, perpage))
        else:
            cursor.execute('SELECT * FROM commands LIMIT %s, %s;', (startat, perpage))

        data = list(cursor.fetchall())

        # Menghitung total halaman dengan atau tanpa pencarian
        if search_query:
            cursor.execute('SELECT COUNT(*) FROM commands WHERE id LIKE %s OR device_type LIKE %s OR command LIKE %s', (search_like, search_like, search_like))
        else:
            cursor.execute('SELECT COUNT(*) FROM commands')
        total = cursor.fetchone()
        total_pages = total['COUNT(*)'] // perpage + (total['COUNT(*)'] % perpage > 0)

        # Logika pagination
        left_window = max(1, page - 2)
        right_window = min(total_pages, page + 2)
        
        cursor.close()
        connection.close()

    if 'username' in session:
        username = session['username']
        return render_template('type.html', commands=data, username=username, page=page, total_pages=total_pages, left_window=left_window, right_window=right_window, search_query=search_query)
    return redirect(url_for('login'))

def get_device_types():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT device_type FROM commands")
        device_types = cursor.fetchall()
        cursor.close()
        connection.close()
        return device_types
    return []

@app.route('/edit-type/<int:id>', methods=['GET'])
@login_required
def edit_type(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM commands WHERE id = %s", (id,))
        device_type = cursor.fetchone()
        cursor.close()
        connection.close()

    if device_type:
        if 'username' in session:
            username = session['username']
            return render_template('edit_type.html', device_type=device_type, username=username)
    flash('Device Type Not Found', 'danger')
    return redirect(url_for('view_type'))

@app.route('/delete-type/<int:id>', methods=['GET'])
@login_required
def delete_type(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("DELETE FROM commands WHERE id = %s", (id,))
            connection.commit()
            flash('Delete Success', 'success')
        except Exception as e:
            flash(f'Error Deleting Device :  {str(e)}', 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('view_type'))

@app.route('/update-type', methods=['POST'])
@login_required
def update_type():
    id = request.form['id']
    device_type = request.form['device_type']
    command = request.form['command']

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("UPDATE commands SET device_type=%s, command=%s WHERE id=%s", (device_type, command, id))
            connection.commit()
            flash('Update Success', 'success')
        except Exception as e:
            flash(f'Error Update{str(e)}', 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('view_type'))

@app.route('/add-type', methods=['GET'])
@login_required
def form_tambah_type():
    if 'username' in session:
        username = session['username']
        return render_template('add_type.html', username=username)
    return redirect(url_for('login'))

@app.route('/add-type', methods=['POST'])
@login_required
def tambah_type():
    device_type = request.form['device_type']
    command = request.form['command']

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("INSERT INTO commands (device_type, command) VALUES (%s, %s)", (device_type, command))
            connection.commit()
            flash('Add Success', 'success')
        except Exception as e:
            flash(f'Error Add Device : {str(e)}', 'danger')
        finally:
            cursor.close()
            connection.close()

    return redirect(url_for('view_type'))

@app.route('/export-excel-type')
@login_required
def export_excel_type():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM commands"
        cursor.execute(query)
        result = cursor.fetchall()
        cursor.close()
        connection.close()

    # Konversi hasil query ke DataFrame pandas
    df = pd.DataFrame(result)

    # Tentukan nama file Excel yang akan dihasilkan
    excel_file = BytesIO()
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='commands', index=False)

    excel_file.seek(0)

    # Membuat response
    response = make_response(excel_file.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = 'attachment; filename=Daftar_Type.xlsx'

    return response

@app.route('/upload-excel-type', methods=['POST', 'GET'])
@login_required
def upload_excel_type():
    if request.method == 'POST':
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            if 'file' not in request.files:
                flash('Tidak ada file bagian', 'danger')
                return redirect(request.url)
            file = request.files['file']
    if file.filename == '':
        flash('File not selected', 'danger')
        return redirect(request.url)
    if file and file.filename.endswith('.xlsx'):
        try:
            df = pd.read_excel(file)
            cursor = connection.cursor()
            for index, row in df.iterrows():
                cursor.execute("INSERT INTO commands (device_type, command) VALUES (%s, %s)", 
                               (row['device_type'], row['command']))
            connection.commit()
            cursor.close()
            flash('Data berhasil diimport dari Excel.', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
    else:
        flash('Invalid Format', 'danger')
    return redirect(url_for('view_type'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        if request.method == 'POST':
            next_backup_time_str = request.form['next_backup_time']
            next_backup_time = datetime.strptime(next_backup_time_str, '%Y-%m-%dT%H:%M')
            backup_frequency = request.form['backup_frequency']
            try:
                cursor.execute("UPDATE settings SET next_backup_time = %s, backup_frequency = %s WHERE id = 1", (next_backup_time, backup_frequency))
                connection.commit()
                flash('Update Success', 'success')
            except Exception as e:
                flash(f'Error Update Settings: {str(e)}', 'danger')
        
        cursor.execute("SELECT next_backup_time, backup_frequency FROM settings WHERE id = 1")
        setting = cursor.fetchone()
        cursor.close()
        connection.close()

    if 'username' in session:
        username = session['username']
        return render_template('settings.html', setting=setting, username=username)
    return redirect(url_for('login'))

@app.route('/edit_settings/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_settings(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        if request.method == 'POST':
            next_backup_time_str = request.form['next_backup_time']
            next_backup_time = datetime.strptime(next_backup_time_str, '%Y-%m-%dT%H:%M')
            backup_frequency = request.form['backup_frequency']
            cursor.execute("UPDATE settings SET next_backup_time = %s, backup_frequency = %s WHERE id = %s", (next_backup_time, backup_frequency, id))
            connection.commit()
            flash('Update Success', 'success')
            return redirect(url_for('settings'))
        
        cursor.execute("SELECT next_backup_time, backup_frequency FROM settings WHERE id = %s", (id,))
        setting = cursor.fetchone()
        cursor.close()
        connection.close()

    if setting:
        return render_template('edit_settings.html', setting=setting)
    flash('Device Not Found', 'danger')
    return redirect(url_for('settings'))

@app.route('/delete_settings/<int:id>', methods=['POST'])
@login_required
def delete_settings(id):
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("DELETE FROM settings WHERE id = %s", (id,))
            connection.commit()
            flash('Delete Success', 'success')
        except Exception as e:
            flash(f'Error Delete {str(e)}', 'danger')
        finally:
            cursor.close()
            connection.close()
    return redirect(url_for('settings'))

def schedule_backup():
    with app.app_context():
        trigger_backup()

def update_scheduler():
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT next_backup_time, backup_frequency FROM settings WHERE id = 1")
        setting = cursor.fetchone()
        cursor.close()
        connection.close()

        if setting and setting['next_backup_time']:
            next_backup_time = setting['next_backup_time']
            backup_frequency = setting['backup_frequency']
            scheduler.remove_all_jobs()

            if backup_frequency == 'daily':
                scheduler.add_job(func=schedule_backup, trigger="interval", days=1, start_date=next_backup_time)
            elif backup_frequency == 'weekly':
                scheduler.add_job(func=schedule_backup, trigger="interval", weeks=1, start_date=next_backup_time)
            elif backup_frequency == 'monthly':
                scheduler.add_job(func=schedule_backup, trigger="interval", weeks=4, start_date=next_backup_time)

# Inisialisasi scheduler
scheduler = BackgroundScheduler()
update_scheduler()
scheduler.start()

if __name__ == '__main__':
    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
