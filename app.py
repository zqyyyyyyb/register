from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2 import sql
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)


# 数据库连接函数
def get_db_connection():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    return conn


# 创建表（首次运行）
def create_tables():
    conn = get_db_connection()
    cur = conn.cursor()

    # 创建有效工号表
    cur.execute("""
    CREATE TABLE IF NOT EXISTS valid_ids (
        id SERIAL PRIMARY KEY,
        employee_id VARCHAR(20) NOT NULL UNIQUE,
        is_used BOOLEAN DEFAULT FALSE
    )
    """)

    # 创建用户表
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        employee_id VARCHAR(20) NOT NULL UNIQUE,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(100) NOT NULL
    )
    """)

    # 插入示例工号
    cur.execute("""
    INSERT INTO valid_ids (employee_id)
    VALUES ('EMP001'), ('EMP002'), ('EMP003')
    ON CONFLICT (employee_id) DO NOTHING
    """)

    conn.commit()
    cur.close()
    conn.close()


# 密码加密
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


# 验证密码
def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))


# 初始化数据库
create_tables()


# API端点
@app.route('/')
def home():
    return jsonify({"status": "API Running", "version": "1.0"})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    employee_id = data.get('employee_id')
    username = data.get('username')
    password = data.get('password')

    if not all([employee_id, username, password]):
        return jsonify({"error": "缺少必要字段"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # 验证工号
        cur.execute("SELECT * FROM valid_ids WHERE employee_id = %s AND is_used = FALSE", (employee_id,))
        valid_id = cur.fetchone()

        if not valid_id:
            return jsonify({"error": "无效或已使用的工号"}), 400

        # 检查用户名是否已存在
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({"error": "用户名已存在"}), 400

        # 创建用户
        hashed_pw = hash_password(password)
        cur.execute(
            "INSERT INTO users (employee_id, username, password) VALUES (%s, %s, %s)",
            (employee_id, username, hashed_pw)
        )

        # 标记工号已使用
        cur.execute(
            "UPDATE valid_ids SET is_used = TRUE WHERE employee_id = %s",
            (employee_id,)
        )

        conn.commit()
        return jsonify({"message": "注册成功"}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    employee_id = data.get('employee_id')
    password = data.get('password')

    if not employee_id or not password:
        return jsonify({"error": "缺少工号或密码"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("SELECT * FROM users WHERE employee_id = %s", (employee_id,))
        user = cur.fetchone()

        if user and check_password(user[3], password):
            return jsonify({
                "message": "登录成功",
                "username": user[2]
            }), 200

        return jsonify({"error": "工号或密码错误"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)