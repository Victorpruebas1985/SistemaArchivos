import os
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# 1. Configuración de la App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi_secreto_seguro_123' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads' # Carpeta donde se guardan los archivos físicos

# 2. Inicializar extensiones
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# Generador de Tokens (Usa tu SECRET_KEY para firmarlos)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 3. Modelos de Base de Datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # --- NUEVA LÍNEA ---
    email = db.Column(db.String(150), unique=True, nullable=False) 
    # -------------------
    password = db.Column(db.String(150), nullable=False)
    files = db.relationship('File', backref='owner')
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300))
    # Vinculamos el archivo a un usuario (Dueño)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_public = db.Column(db.Boolean, default=False)

# 4. Loader de usuario (Requerido por Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 5. Rutas
@app.route('/')
def home():
    # Buscar todos los archivos donde is_public es True
    public_files = File.query.filter_by(is_public=True).all()
    return render_template('home.html', files=public_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') # <--- Capturamos el email
        password = request.form.get('password')

        # Verificar si usuario O email ya existen
        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('El nombre de usuario o el correo ya están registrados.')
            return redirect(url_for('register'))

        # Crear usuario con email
        new_user = User(username=username, email=email, password=generate_password_hash(password, method='scrypt'))
        
        db.session.add(new_user)
        db.session.commit()
        
        return "<h1>¡Usuario creado! <a href='/login'>Ir al Login</a></h1>"

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
            flash('Usuario o contraseña incorrectos.')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Pasamos los archivos del usuario actual a la plantilla HTML
    return render_template('dashboard.html', name=current_user.username, files=current_user.files)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Nombre de archivo vacío')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        
        # Guardar físico
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # --- CAPTURAR SI ES PÚBLICO ---
        # El checkbox HTML envía 'on' si está marcado, o None si no.
        is_public_val = True if request.form.get('is_public') == 'on' else False
        
        new_file = File(filename=filename, owner=current_user, is_public=is_public_val)
        # ------------------------------

        db.session.add(new_file)
        db.session.commit()
        
        flash('Archivo subido exitosamente')
        return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
# NOTA: NO ponemos @login_required aquí porque queremos permitir descargas públicas
def download(file_id):
    file_data = File.query.get_or_404(file_id) 
    
    # CASO 1: Si el archivo es PÚBLICO -> Cualquiera puede bajarlo
    if file_data.is_public:
        return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)

    # CASO 2: Si el archivo es PRIVADO -> Verificamos que estés logueado y seas el dueño
    if not current_user.is_authenticated:
        flash('Debes iniciar sesión para ver este archivo privado.')
        return redirect(url_for('login'))

    if file_data.owner != current_user:
        flash('¡No tienes permiso para ver este archivo!')
        return redirect(url_for('dashboard'))

    # Si pasaste las validaciones, te enviamos el archivo
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_data.filename, as_attachment=True)
@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    file_to_delete = File.query.get_or_404(file_id)

    # 1. Seguridad: Verificar que el usuario sea el dueño
    if file_to_delete.owner != current_user:
        flash('¡No tienes permiso para eliminar este archivo!')
        return redirect(url_for('dashboard'))

    # 2. Borrar el archivo físico de la carpeta 'uploads'
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        print(f"Error al borrar archivo físico: {e}")

    # 3. Borrar el registro de la base de datos
    db.session.delete(file_to_delete)
    db.session.commit()

    flash('Archivo eliminado correctamente.')
    return redirect(url_for('dashboard'))

# Ruta 1: Solicitar recuperación
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generar token (Vence en 3600 segundos = 1 hora)
            token = serializer.dumps(user.email, salt='recuperar-clave')
            
            # Crear el link completo
            link = url_for('reset_password', token=token, _external=True)
            
            # SIMULACIÓN DE EMAIL: Imprimir en la terminal
            print(f"\n========================================")
            print(f"📧 SIMULACIÓN DE EMAIL PARA: {email}")
            print(f"🔗 LINK DE RECUPERACIÓN: {link}")
            print(f"========================================\n")
            
            flash('Se ha enviado un enlace de recuperación a tu correo (¡Mira la terminal!).')
            return redirect(url_for('login'))
        else:
            flash('Ese correo no está registrado.')

    return render_template('forgot_password.html')

# Ruta 2: Cambiar la contraseña usando el Token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verificar token (Max 1 hora de antigüedad)
        email = serializer.loads(token, salt='recuperar-clave', max_age=3600)
    except:
        flash('El enlace es inválido o ha expirado.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        
        # Buscar usuario y actualizar contraseña
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password, method='scrypt')
        db.session.commit()

        flash('¡Tu contraseña ha sido actualizada! Inicia sesión.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/toggle_privacy/<int:file_id>')
@login_required
def toggle_privacy(file_id):
    file = File.query.get_or_404(file_id)
    
    # Seguridad: Verificar que eres el dueño
    if file.owner != current_user:
        flash('No tienes permiso para modificar este archivo.')
        return redirect(url_for('dashboard'))
    
    # EL INTERRUPTOR: Cambiar de True a False o viceversa
    file.is_public = not file.is_public
    db.session.commit()
    
    # Mensaje de confirmación
    status = "PÚBLICO 🌍" if file.is_public else "PRIVADO 🔒"
    flash(f'El archivo "{file.filename}" ahora es {status}.')
    
    return redirect(url_for('dashboard'))
# 6. Arranque
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crea las tablas si no existen
    app.run(debug=True)