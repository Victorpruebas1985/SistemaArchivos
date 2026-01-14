import os
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

# 4. Loader de usuario (Requerido por Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 5. Rutas
@app.route('/')
def home():
    return "<h1>Sistema de Archivos Activo. <br> <a href='/login'>Iniciar Sesión</a> o <a href='/register'>Registrarse</a></h1>"

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
    # Verificamos si la petición tiene la parte del archivo
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('Nombre de archivo vacío')
        return redirect(url_for('dashboard'))

    if file:
        filename = secure_filename(file.filename)
        
        # 1. Guardar archivo físico en la carpeta
        # Asegúrate de haber creado la carpeta 'uploads'
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # 2. Guardar registro en la base de datos vinculado al usuario
        new_file = File(filename=filename, owner=current_user)
        db.session.add(new_file)
        db.session.commit()
        
        flash('Archivo subido exitosamente')
        return redirect(url_for('dashboard'))
@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file_data = File.query.get_or_404(file_id) # Busca el archivo o da error 404 si no existe

    # SEGURIDAD: Verificar que el archivo pertenezca al usuario logueado
    if file_data.owner != current_user:
        flash('¡No tienes permiso para ver este archivo!')
        return redirect(url_for('dashboard'))

    # Enviar el archivo
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
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 6. Arranque
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crea las tablas si no existen
    app.run(debug=True)