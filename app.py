from flask import Flask, render_template, request, redirect, session, jsonify, flash
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
import random
import string
import os
from datetime import datetime, timedelta

app = Flask(__name__)
#app.secret_key = 'copper_secret_key_@!2023'
app.secret_key = os.environ['SECRET_KEY']

# MySQL配置
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'pmd90@SQ'  # 替换为你的MySQL密码
app.config['MYSQL_DB'] = 'copper_certification'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# 创建所需数据表（如果不存在）
def create_tables():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                role ENUM('admin', 'worker') NOT NULL DEFAULT 'worker',
                status ENUM('pending', 'certified') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                worker_id INT NOT NULL,
                worker_name VARCHAR(50),
                issue_date DATE NOT NULL,
                expiry_date DATE NOT NULL,
                verification_code VARCHAR(12) UNIQUE NOT NULL,
                certificate_data TEXT,
                FOREIGN KEY (worker_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        # 创建管理员账户（如果不存在）
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        admin = cur.fetchone()
        if not admin:
            password = sha256_crypt.hash('admin_password')  # 替换为你的管理员密码
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, 'admin')", 
                ('admin', password)
            )
        mysql.connection.commit()

create_tables()

# 首页
@app.route('/')
def home():
    return render_template('home.html')

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cur.fetchone()
        
        if user and sha256_crypt.verify(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('登录成功!', 'success')
            return redirect('/dashboard')
        else:
            flash('用户名或密码错误!', 'danger')
    return render_template('login.html')

# 退出登录
@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功退出登录', 'success')
    return redirect('/login')

# 控制面板
@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect('/login')
    
    cur = mysql.connection.cursor()
    if session['role'] == 'admin':
        # 获取所有工人信息
        cur.execute("SELECT id, username, role, status, created_at FROM users WHERE role='worker'")
        workers = cur.fetchall()
        
        # 获取统计信息
        cur.execute("SELECT COUNT(*) as total FROM users")
        total_users = cur.fetchone()['total']
        
        cur.execute("SELECT COUNT(*) as total FROM certificates")
        total_certs = cur.fetchone()['total']
        
        cur.execute("SELECT COUNT(*) as total FROM certificates WHERE expiry_date < CURDATE()")
        expired_certs = cur.fetchone()['total']
        
        return render_template('admin_dash.html', 
                              workers=workers,
                              total_users=total_users,
                              total_certs=total_certs,
                              expired_certs=expired_certs)
    else:
        # 工人面板
        cur.execute("""
            SELECT c.id, c.verification_code, c.issue_date, c.expiry_date, c.certificate_data
            FROM certificates c
            WHERE c.worker_id = %s
            ORDER BY c.issue_date DESC
        """, [session['user_id']])
        certs = cur.fetchall()
        
        # 获取工人信息
        cur.execute("SELECT * FROM users WHERE id = %s", [session['user_id']])
        worker_info = cur.fetchone()
        
        return render_template('worker_dash.html', 
                              certificates=certs, 
                              worker_info=worker_info)

# 添加工人
@app.route('/admin/add_worker', methods=['POST'])
def add_worker():
    if session.get('role') != 'admin': 
        flash('无权访问!', 'danger')
        return redirect('/login')
    
    username = request.form['username']
    password = request.form['password']
    
    # 验证用户名是否已存在
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    if cur.fetchone():
        flash('用户名已存在!', 'danger')
        return redirect('/dashboard')
    
    hashed_pw = sha256_crypt.hash(password)
    
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                (username, hashed_pw))
    mysql.connection.commit()
    flash('工人添加成功!', 'success')
    return redirect('/dashboard')

# 工人认证
@app.route('/admin/certify/<int:worker_id>', methods=['GET', 'POST'])
def certify_worker(worker_id):
    if session.get('role') != 'admin': 
        return redirect('/login')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [worker_id])
    worker = cur.fetchone()
    
    if not worker:
        flash('工人不存在!', 'danger')
        return redirect('/dashboard')
    
    if request.method == 'POST':
        # 生成唯一认证码
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        issue_date = datetime.now().strftime('%Y-%m-%d')
        expiry_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')
        
        # 准备认证书数据
        certificate_data = request.form.get('certificate_data', '')
        
        cur.execute("""
            INSERT INTO certificates (worker_id, worker_name, issue_date, expiry_date, verification_code, certificate_data) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            worker_id,
            worker['username'],
            issue_date,
            expiry_date,
            code,
            certificate_data
        ))
        
        # 更新工人状态
        cur.execute("UPDATE users SET status='certified' WHERE id=%s", [worker_id])
        mysql.connection.commit()
        flash(f'{worker["username"]} 认证成功! 证书ID: {code}', 'success')
        return redirect('/dashboard')
    
    return render_template('certify.html', worker=worker)

# 删除工人
@app.route('/admin/delete_worker/<int:worker_id>', methods=['POST'])
def delete_worker(worker_id):
    if session.get('role') != 'admin': 
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", [worker_id])
        mysql.connection.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 查询功能
@app.route('/search')
def search():
    query = request.args.get('q', '')
    cur = mysql.connection.cursor()
    
    cur.execute("""
        SELECT u.username, u.status, c.verification_code, c.issue_date, c.expiry_date 
        FROM certificates c
        JOIN users u ON u.id = c.worker_id
        WHERE verification_code LIKE %s OR u.username LIKE %s
    """, [f'%{query}%', f'%{query}%'])
    
    results = cur.fetchall()
    return render_template('results.html', results=results, query=query)

# 查看证书详情
@app.route('/certificate/<verification_code>')
def view_certificate(verification_code):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.*, u.username
        FROM certificates c
        JOIN users u ON u.id = c.worker_id
        WHERE verification_code = %s
    """, [verification_code])
    
    certificate = cur.fetchone()
    if not certificate:
        flash('证书未找到', 'danger')
        return redirect('/search')
    
    return render_template('certificate_detail.html', certificate=certificate)

# 更改密码
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('user_id'):
        return redirect('/login')
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('新密码不匹配', 'danger')
            return redirect('/change_password')
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT password FROM users WHERE id = %s", [session['user_id']])
        user = cur.fetchone()
        
        if user and sha256_crypt.verify(current_password, user['password']):
            hashed_pw = sha256_crypt.hash(new_password)
            cur.execute("UPDATE users SET password = %s WHERE id = %s", 
                       (hashed_pw, session['user_id']))
            mysql.connection.commit()
            flash('密码更新成功!', 'success')
            return redirect('/dashboard')
        else:
            flash('当前密码错误', 'danger')
    
    return render_template('change_password.html')

# 下载证书
@app.route('/download_certificate/<verification_code>')
def download_certificate(verification_code):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.*, u.username
        FROM certificates c
        JOIN users u ON u.id = c.worker_id
        WHERE verification_code = %s
    """, [verification_code])
    
    certificate = cur.fetchone()
    if not certificate:
        flash('证书未找到', 'danger')
        return redirect('/search')
    
    # 简单实现证书下载功能
    response = f"铜水管工认证书\n\n"
    response += f"证书编号: {certificate['verification_code']}\n"
    response += f"工人姓名: {certificate['username']}\n"
    response += f"发证日期: {certificate['issue_date']}\n"
    response += f"有效期至: {certificate['expiry_date']}\n\n"
    response += "此证书证明持有者已完成铜水管安装与维修专业培训，符合行业标准要求。\n"
    response += "证书信息可通过官方查询系统验证: http://121.43.75.25/search?q={}\n".format(
        certificate['verification_code']
    )
    
    return response, 200, {
        'Content-Disposition': f'attachment; filename={certificate["verification_code"]}.txt',
        'Content-type': 'text/plain'
    }

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)