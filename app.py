import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from thefuzz import process  # Librería para búsqueda inteligente

# ==========================================
# 1. CONFIGURACIÓN DEL SISTEMA
# ==========================================
app = Flask(__name__)

# Configuración de seguridad y base de datos
app.config['SECRET_KEY'] = 'mi_secreto_super_seguro' # Cambiar en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de carpeta de archivos
app.config['UPLOAD_FOLDER'] = 'uploads'

# Crear la carpeta de subidas si no existe
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Inicializar extensiones
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirigir aquí si no están logueados

# Generador de tokens para recuperar contraseña
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ==========================================
# 2. MODELOS DE BASE DE DATOS
# ==========================================

class User(UserMixin, db.Model):
    """Modelo de Usuario con Roles"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    # Roles: 'administrativo', 'tecnico', 'medico', 'superadmin'
    role = db.Column(db.String(50), nullable=False, default='administrativo')
    
    # Relación con archivos (si borras usuario, se borran sus archivos de la DB)
    files = db.relationship('File', backref='owner', lazy=True, cascade="all, delete-orphan")

class File(db.Model):
    """Modelo de Archivo con Visibilidad"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Visibilidad: 'private', 'public', 'salud', 'admin'
    visibility = db.Column(db.String(50), default='private')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==========================================
# 3. LÓGICA DE PERMISOS (CEREBRO 🧠)
# ==========================================

def get_allowed_files(user):
    """
    Determina qué archivos puede ver un usuario según su rol.
    Retorna una lista de objetos File.
    """
    # CASO 1: Superadmin ve TODO
    if user.is_authenticated and user.role == 'superadmin':
        return File.query.all()

    # CASO 2: Usuarios normales
    filters = [File.visibility == 'public'] # Todos ven lo público

    if user.is_authenticated:
        # Siempre ver mis propios archivos
        filters.append(File.owner == user)

        # Filtros por grupos de trabajo
        if user.role in ['medico', 'tecnico']:
            filters.append(File.visibility == 'salud')
        elif user.role == 'administrativo':
            filters.append(File.visibility == 'admin')

    # Combinar filtros (OR)
    return File.query.filter(db.or_(*filters)).all()

# ==========================================
# 4. RUTAS PRINCIPALES (HOME Y DASHBOARD)
# ==========================================

@app.route('/')
def home():
    """Página de inicio con buscador"""
    # Usamos current_user (Flask-Login maneja si es anónimo o no)
    files = get_allowed_files(current_user)
    return render_template('home.html', files=files)

@app.route('/dashboard')
@login_required
def dashboard():
    """Panel de control del usuario"""
    users = [] # Lista de usuarios (solo para superadmin)

    if current_user.role == 'superadmin':
        # MODO DIOS: Ve todo
        files = File.query.all()
        users = User.query.all()
    else:
        # MODO NORMAL: Solo ve lo suyo
        files = File.query.filter_by(user_id=current_user.id).all()
        
    return render_template('dashboard.html', 
                         name=current_user.username, 
                         role=current_user.role, 
                         files=files, 
                         users=users)

# ==========================================
# 5. GESTIÓN DE ARCHIVOS (SUBIDA Y DESCARGA)
# ==========================================

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    """Ruta para subir archivos"""
    if 'file' not in request.files:
        flash('No se seleccionó archivo')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Nombre de archivo vacío')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        # Guardar en disco
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Obtener visibilidad del formulario
        visibility_option = request.form.get('visibility')
        valid_options = ['private', 'public', 'salud', 'admin']
        if visibility_option not in valid_options:
            visibility_option = 'private'

        # Guardar en Base de Datos
        new_file = File(filename=filename, owner=current_user, visibility=visibility_option)
        db.session.add(new_file)
        db.session.commit()
        
        flash('Archivo subido exitosamente.')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    """Ruta inteligente de descarga con validación de permisos"""
    file_data = File.query.get_or_404(file_id)
    
    # 1. Pase VIP Superadmin
    if current_user.is_authenticated and current_user.role == 'superadmin':
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

    # 2. Archivos Públicos
    if file_data.visibility == 'public':
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

    # 3. Archivos Privados/Grupales (Requieren Login)
    if not current_user.is_authenticated:
        flash('Debes iniciar sesión.')
        return redirect(url_for('login'))

    # Si es dueño
    if file_data.owner == current_user:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

    # Si es del grupo correcto
    allowed = False
    if file_data.visibility == 'salud' and current_user.role in ['medico', 'tecnico']:
        allowed = True
    elif file_data.visibility == 'admin' and current_user.role == 'administrativo':
        allowed = True
        
    if allowed:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)
    
    flash('Acceso denegado.')
    return redirect(url_for('home'))

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    """Borrar archivo (Dueño o Superadmin)"""
    file = File.query.get_or_404(file_id)

    # Permiso: Dueño O Superadmin
    if file.owner != current_user and current_user.role != 'superadmin':
        flash('No tienes permiso para borrar esto.')
        return redirect(url_for('dashboard'))
    
    # Borrado físico
    try:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        print(f"Error borrando archivo físico: {e}")
    
    # Borrado DB
    db.session.delete(file)
    db.session.commit()
    flash('Archivo eliminado.')
    return redirect(url_for('dashboard'))

# ==========================================
# 6. AUTENTICACIÓN Y USUARIOS
# ==========================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Backdoor Superadmin
        if username == 'admin_supremo':
            role = 'superadmin'

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Usuario o email ya existen.')
            return redirect(url_for('register'))

        new_user = User(
            username=username, 
            email=email, 
            role=role, 
            password=generate_password_hash(password, method='scrypt')
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Cuenta creada. Inicia sesión.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

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
            flash('Datos incorrectos.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    """Función Superadmin para borrar usuarios y sus archivos"""
    if current_user.role != 'superadmin':
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('No puedes borrarte a ti mismo.')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    
    # Borrar archivos físicos del usuario
    for f in user.files:
        try:
            path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            if os.path.exists(path): os.remove(path)
        except: pass

    db.session.delete(user)
    db.session.commit()
    flash(f'Usuario {user.username} eliminado.')
    return redirect(url_for('dashboard'))

# ==========================================
# 7. EXTRAS (API BUSCADOR Y RECUPERAR CLAVE)
# ==========================================

@app.route('/api/search_suggestions')
def search_suggestions():
    """API para el autocompletado del buscador"""
    query = request.args.get('q', '')
    if len(query) < 2: return jsonify([])

    # Obtener archivos permitidos para quien busca
    allowed_files = get_allowed_files(current_user)
    files_map = {f.filename: f.id for f in allowed_files}
    all_filenames = list(files_map.keys())

    # Búsqueda difusa (Fuzzy)
    matches = process.extract(query, all_filenames, limit=5)
    
    suggestions = []
    for match in matches:
        if match[1] > 50: # Umbral de similitud
            suggestions.append({
                'filename': match[0],
                'id': files_map[match[0]],
                'score': match[1]
            })

    return jsonify(suggestions)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Lógica simplificada de solicitud
    if request.method == 'POST':
        email = request.form.get('email')
        flash('Si el correo existe, verás el link en la terminal del servidor.')
        # Aquí iría la lógica real de envío de email
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Lógica simplificada de reset
    if request.method == 'POST':
        flash('Contraseña actualizada.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ==========================================
# 8. ARRANQUE
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crear tablas si no existen
    app.run(debug=True)