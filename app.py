import logging
from flask import Flask, request, render_template, jsonify
import sqlite3
import os
import re
import bcrypt

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

app = Flask(__name__, template_folder='../front/templates', static_folder='../front/static')

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_file(file):
    allowed_types = ['image/jpeg', 'image/png', 'image/gif']
    max_size = 2 * 1024 * 1024
    if file.mimetype not in allowed_types:
        return False, 'Недопустимый тип файла. Разрешены только JPEG, PNG, GIF.'
    if file.content_length > max_size:
        return False, 'Файл слишком большой. Максимальный размер: 2MB.'
    return True, ''

def is_valid_full_name(full_name):
    words = full_name.strip().split()
    return len(words) == 3, 'ФИО должно содержать ровно три слова (Фамилия, Имя, Отчество).'

def is_strong_password(password):
    return (
        len(password) >= 8 and
        bool(re.search(r'\d', password)) and
        bool(re.search(r'[a-zA-Zа-яА-Я]', password)) and
        bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def init_db():
    if not os.path.exists('database.db'):
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                about TEXT NOT NULL,
                avatar BLOB
            )''')
            conn.commit()
        logging.info("База данных успешно инициализирована")

init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        about = request.form.get('about')
        avatar = request.files.get('avatar')

        logging.info(f"Попытка регистрации: login={login}, full_name={full_name}, email={email}, phone={phone}, about={about}")

        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE login = ?', (login,))
            if c.fetchone():
                logging.warning(f"Ошибка регистрации: логин {login} уже существует")
                return "Этот логин уже занят!"

        if not full_name:
            logging.warning(f"Ошибка регистрации: поле ФИО пустое для login={login}")
            return "Поле ФИО обязательно для заполнения!"

        is_valid, full_name_error = is_valid_full_name(full_name)
        if not is_valid:
            logging.warning(f"Ошибка регистрации: {full_name_error} для login={login}")
            return full_name_error

        if not is_valid_email(email):
            logging.warning(f"Ошибка регистрации: неверный формат email={email}")
            return "Неверный формат email!"

        if password != confirm_password:
            logging.warning(f"Ошибка регистрации: пароли не совпадают для login={login}")
            return "Пароли не совпадают!"

        if not is_strong_password(password):
            logging.warning(f"Ошибка регистрации: пароль не соответствует требованиям для login={login}")
            return "Пароль должен содержать минимум 8 символов, цифры, буквы и специальные символы!"

        if avatar:
            is_valid, error_message = is_valid_file(avatar)
            if not is_valid:
                logging.warning(f"Ошибка регистрации: {error_message} для login={login}")
                return error_message
            avatar_data = avatar.read()
        else:
            logging.warning(f"Ошибка регистрации: файл аватара не загружен для login={login}")
            return "Файл аватара обязателен!"

        try:
            hashed_password = hash_password(password)
            with sqlite3.connect('database.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO users (login, password, full_name, email, phone, about, avatar)
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (login, hashed_password, full_name, email, phone, about, avatar_data))
                conn.commit()
            logging.info(f"Пользователь успешно зарегистрирован: login={login}")
        except Exception as e:
            logging.error(f"Ошибка при сохранении пользователя login={login}: {str(e)}")
            return "Произошла ошибка сервера"

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, login, full_name, email, phone, about FROM users')
        users = c.fetchall()

    return render_template('index.html', users=users)

@app.route('/api/users', methods=['POST'])
def api_users():
    data = request.form
    login = data.get('login')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    full_name = data.get('full_name')
    email = data.get('email')
    phone = data.get('phone')
    about = data.get('about')
    avatar = request.files.get('avatar')

    logging.info(f"API: Попытка регистрации: login={login}, full_name={full_name}, email={email}, phone={phone}, about={about}")

    if not all([login, password, confirm_password, full_name, email, phone, about]):
        logging.warning(f"API: Ошибка регистрации: не все обязательные поля заполнены для login={login}")
        return jsonify({
            'status': 'error',
            'message': 'Все обязательные поля должны быть заполнены'
        }), 400

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE login = ?', (login,))
        if c.fetchone():
            logging.warning(f"API: Ошибка регистрации: логин {login} уже существует")
            return jsonify({
                'status': 'error',
                'message': 'Этот логин уже занят'
            }), 400

    is_valid, full_name_error = is_valid_full_name(full_name)
    if not is_valid:
        logging.warning(f"API: Ошибка регистрации: {full_name_error} для login={login}")
        return jsonify({
            'status': 'error',
            'message': full_name_error
        }), 400

    if not is_valid_email(email):
        logging.warning(f"API: Ошибка регистрации: неверный формат email={email}")
        return jsonify({
            'status': 'error',
            'message': 'Неверный формат email'
        }), 400

    if password != confirm_password:
        logging.warning(f"API: Ошибка регистрации: пароли не совпадают для login={login}")
        return jsonify({
            'status': 'error',
            'message': 'Пароли не совпадают'
        }), 400

    if not is_strong_password(password):
        logging.warning(f"API: Ошибка регистрации: пароль не соответствует требованиям для login={login}")
        return jsonify({
            'status': 'error',
            'message': 'Пароль должен содержать минимум 8 символов, цифры, буквы и специальные символы'
        }), 400

    if avatar:
        is_valid, error_message = is_valid_file(avatar)
        if not is_valid:
            logging.warning(f"API: Ошибка регистрации: {error_message} для login={login}")
            return jsonify({
                'status': 'error',
                'message': error_message
            }), 400
        avatar_data = avatar.read()
    else:
        logging.warning(f"API: Ошибка регистрации: файл аватара не загружен для login={login}")
        return jsonify({
            'status': 'error',
            'message': 'Файл аватара обязателен'
        }), 400

    try:
        hashed_password = hash_password(password)
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO users (login, password, full_name, email, phone, about, avatar)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (login, hashed_password, full_name, email, phone, about, avatar_data))
            conn.commit()
        logging.info(f"API: Пользователь успешно зарегистрирован: login={login}")
        return jsonify({
            'status': 'success',
            'message': 'Пользователь успешно зарегистрирован',
            'data': {
                'login': login,
                'full_name': full_name,
                'email': email,
                'phone': phone,
                'about': about
            }
        }), 201
    except Exception as e:
        logging.error(f"API: Ошибка при сохранении пользователя login={login}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Произошла ошибка сервера'
        }), 500

if __name__ == '__main__':
    app.run(debug=True)