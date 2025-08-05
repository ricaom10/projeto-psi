from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'projeto_romerito'
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# Caminho para o banco de dados
DB_FILE = 'banco.db'

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'info'

# Função para obter a conexão e criar a tabela se ela não existir
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Permite acessar colunas por nome
    
    # Verifica se a tabela 'users' existe, se não, a cria.
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if not cursor.fetchone():
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()
    
    return conn

# Modelo de Usuário para o Flask-Login
class User(UserMixin):
    def __init__(self, id, email, username):
        self.id = id
        self.email = email
        self.username = username

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT id, email, username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['email'], user_data['username'])
    return None

# Rotas e lógica do carrinho (mantidas do seu código original)
produtos = {
    'roupa_1': {'nome': 'Camisa Esportiva', 'preco': 59.90, 'imagem': 'imagens/roupas/camisa_esportiva.jpg'},
    'roupa_2': {'nome': 'Shorts de Compressão', 'preco': 79.90, 'imagem': 'imagens/roupas/shorts_compressao.jpg'},
    'taco_1': {'nome': 'Taco de beisebol', 'preco': 150.00, 'imagem': 'imagens/tacos/taco_beisebol.jpg'},
    'volei_1': {'nome': 'Bola de vôlei de praia', 'preco': 89.90, 'imagem': 'imagens/volei/bola_volei.jpg'},
}

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        user_cart_key = f'cart_{current_user.id}'
        if user_cart_key not in session:
            session[user_cart_key] = []
    else:
        if 'cart' not in session:
            session['cart'] = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        flash('Você já está logado!', 'info')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('user')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not email or not username or not password or not confirm_password:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('cadastro.html', email=email)

        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return render_template('cadastro.html', email=email)
        
        conn = get_db_connection()
        user_existente = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user_existente:
            conn.close()
            flash('Este email já está cadastrado. Tente outro ou faça login.', 'danger')
            return render_template('cadastro.html', email=email)

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', (username, email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Cadastro realizado com sucesso! Faça login agora.', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('Você já está logado!', 'info')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email_digitado = request.form.get('email')
        senha_digitada = request.form.get('password')
        
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE email = ?', (email_digitado,)).fetchone()
        conn.close()

        if user_data and check_password_hash(user_data['password_hash'], senha_digitada):
            user = User(user_data['id'], user_data['email'], user_data['username'])
            login_user(user)
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha inválidos.', 'danger')
            return render_template('login.html', email=email_digitado)
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_cart_key = f'cart_{current_user.id}'
    if user_cart_key in session:
        session.pop(user_cart_key, None)
    logout_user()
    flash('Você foi desconectado(a).', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/categorias')
def categorias():
    return render_template('categorias.html')

# Rotas de categorias
@app.route('/categorias/roupas')
def roupas():
    return render_template('roupas.html', produtos=produtos)

@app.route('/categorias/futebol')
def futebol():
    return render_template('futebol.html', produtos=produtos)

@app.route('/categorias/basquete')
def basquete():
    return render_template('basquete.html', produtos=produtos)

@app.route('/categorias/volei')
def volei():
    return render_template('volei.html', produtos=produtos)

@app.route('/categorias/ciclismo')
def ciclismo():
    return render_template('ciclismo.html', produtos=produtos)

@app.route('/categorias/aqua')
def aqua():
    return render_template('aqua.html', produtos=produtos)

@app.route('/categorias/tacos')
def tacos():
    return render_template('tacos.html', produtos=produtos)

@app.route('/categorias/automobilismo')
def auto():
    return render_template('auto.html', produtos=produtos)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_image = request.form.get('product_image')
    product_description = request.form.get('product_description')

    if current_user.is_authenticated:
        user_cart_key = f'cart_{current_user.id}'
        cart = session.get(user_cart_key, [])
        if len(cart) >= 12:
            flash('Limite de 12 produtos no carrinho atingido.', 'warning')
        else:
            cart.append({'image': product_image, 'description': product_description})
            session[user_cart_key] = cart
            flash('Produto adicionado ao carrinho!', 'success')
    else:
        cart = session.get('cart', [])
        if len(cart) >= 12:
            flash('Limite de 12 produtos no carrinho atingido.', 'warning')
        else:
            cart.append({'image': product_image, 'description': product_description})
            session['cart'] = cart
            flash('Produto adicionado ao carrinho! Faça login para salvar seu carrinho.', 'success')

    return redirect(request.referrer or url_for('index'))


@app.route('/carrinho')
def carrinho():
    if current_user.is_authenticated:
        user_cart_key = f'cart_{current_user.id}'
        cart_items = session.get(user_cart_key, [])
    else:
        cart_items = session.get('cart', [])
    return render_template('carrinho.html', cart_items=cart_items)

if __name__ == '__main__':
    app.run(debug=True)