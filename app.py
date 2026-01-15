import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from thefuzz import process  # Librería para búsqueda inteligente

# ==========================================
# 1. CONFIGURACIÓN DEL SERVIDOR
# ==========================================
app = Flask(__name__)

# Llave secreta para seguridad (sesiones y tokens)
app.config['SECRET_KEY'] = 'mi_secreto_super_seguro'

# Configuración de la Base de Datos (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de la carpeta de subidas
app.config['UPLOAD_FOLDER'] = 'uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Inicializamos la DB y el Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Serializador para generar tokens de recuperación de contraseña
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ==========================================
# 2. MODELOS DE BASE DE DATOS
# ==========================================

class User(UserMixin, db.Model):
    """Tabla de Usuarios"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    # Relación: Un usuario tiene muchos archivos
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    """Tabla de Archivos"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_public = db.Column(db.Boolean, default=False)  # Verdadero = Público, Falso = Privado

# Cargar usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# 3. RUTAS PÚBLICAS Y DE INICIO
# ==========================================

@app.route('/')
def home():
    """Página de Inicio: Muestra archivos públicos y el buscador."""
    # Buscamos solo los archivos que tienen la bandera pública activada
    public_files = File.query.filter_by(is_public=True).all()
    return render_template('home.html', files=public_files)

# ==========================================
# 4. RUTAS DE AUTENTICACIÓN (Login/Registro)
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Verificamos que no existan duplicados
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('El nombre de usuario o email ya están registrados.')
            return redirect(url_for('register'))

        # Creamos el usuario encriptando la contraseña
        new_user = User(
            username=username, 
            email=email, 
            password=generate_password_hash(password, method='scrypt')
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Cuenta creada con éxito. Por favor inicia sesión.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# ==========================================
# 5. RECUPERACIÓN DE CONTRASEÑA
# ==========================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generamos un token temporal
            token = serializer.dumps(user.email, salt='recuperar-clave')
            link = url_for('reset_password', token=token, _external=True)
            
            # SIMULACIÓN DE EMAIL (Se imprime en la terminal)
            print(f"\n{'='*40}")
            print(f"📧 EMAIL PARA: {email}")
            print(f"🔗 LINK: {link}")
            print(f"{'='*40}\n")
            
            flash('Enlace enviado. Revisa la terminal del servidor.')
            return redirect(url_for('login'))
        else:
            flash('Correo no registrado.')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # El token expira en 1 hora (3600 segundos)
        email = serializer.loads(token, salt='recuperar-clave', max_age=3600)
    except:
        flash('El enlace es inválido o ha expirado.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        # Actualizamos la contraseña
        user.password = generate_password_hash(password, method='scrypt')
        db.session.commit()

        flash('Contraseña actualizada correctamente.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ==========================================
# 6. GESTIÓN DE ARCHIVOS (Dashboard)
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    # Solo mostramos los archivos del usuario logueado
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', name=current_user.username, files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No se seleccionó archivo')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Nombre de archivo vacío')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Capturamos si el usuario marcó el checkbox "Público"
        is_public_val = True if request.form.get('is_public') == 'on' else False
        
        new_file = File(filename=filename, owner=current_user, is_public=is_public_val)
        db.session.add(new_file)
        db.session.commit()
        
        flash('Archivo subido exitosamente.')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    """Permite descargar si es público O si eres el dueño."""
    file_data = File.query.get_or_404(file_id)

    # 1. Si es público, cualquiera lo baja
    if file_data.is_public:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

    # 2. Si es privado, validamos sesión y propiedad
    if not current_user.is_authenticated:
        flash('Debes iniciar sesión para ver este archivo.')
        return redirect(url_for('login'))

    if file_data.owner != current_user:
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))

    return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    file_to_delete = File.query.get_or_404(file_id)

    if file_to_delete.owner != current_user:
        flash('No puedes borrar archivos de otros.')
        return redirect(url_for('dashboard'))

    # Borrado físico
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"Error borrando archivo: {e}")

    # Borrado de base de datos
    db.session.delete(file_to_delete)
    db.session.commit()
    flash('Archivo eliminado.')
    return redirect(url_for('dashboard'))

@app.route('/toggle_privacy/<int:file_id>')
@login_required
def toggle_privacy(file_id):
    """Interruptor para cambiar entre Público y Privado"""
    file = File.query.get_or_404(file_id)
    
    if file.owner != current_user:
        flash('Acceso denegado.')
        return redirect(url_for('dashboard'))
    
    # Invertimos el valor (True -> False / False -> True)
    file.is_public = not file.is_public
    db.session.commit()
    
    estado = "PÚBLICO 🌍" if file.is_public else "PRIVADO 🔒"
    flash(f'Archivo "{file.filename}" ahora es {estado}.')
    return redirect(url_for('dashboard'))

# ==========================================
# 7. API DE BUSCADOR INTELIGENTE (Fuzzy Search)
# ==========================================

@app.route('/api/search_suggestions')
def search_suggestions():
    """Devuelve JSON con sugerencias de archivos, tolerando errores ortográficos."""
    query = request.args.get('q', '')
    
    if len(query) < 2:
        return jsonify([])

    # Filtramos qué archivos puede ver el usuario actual
    if current_user.is_authenticated:
        files_query = File.query.filter(
            (File.owner == current_user) | (File.is_public == True)
        ).all()
    else:
        files_query = File.query.filter_by(is_public=True).all()

    # Mapeamos Nombres -> Objetos
    files_map = {f.filename: f.id for f in files_query}
    all_filenames = list(files_map.keys())

    # Usamos thefuzz para encontrar coincidencias
    matches = process.extract(query, all_filenames, limit=5)

    suggestions = []
    for match in matches:
        filename = match[0]
        score = match[1]
        
        # Umbral de similitud (50%)
        if score > 50:
            suggestions.append({
                'filename': filename,
                'id': files_map[filename],
                'score': score
            })

    return jsonify(suggestions)

# ==========================================
# 8. INICIO DE LA APLICACIÓN
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas si no existen
    app.run(debug=True)