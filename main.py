
import email
from flask import Flask, render_template, flash, redirect, url_for
from flask_bootstrap import Bootstrap


from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, IntegerField, DateField, PasswordField
from wtforms.validators import DataRequired, URL

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


import collections
try:
    from collections import abc
    collections.MutableMapping = abc.MutableMapping
except:
    pass
from flask_nav import Nav
from flask_nav.elements import Navbar, View


from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
Bootstrap(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///supplies.db"
db = SQLAlchemy(app)

class Vendors(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    site = db.Column(db.String(250), nullable=False)

class Items(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    vendor = db.Column(db.Integer, nullable=False)
    date_purchase = db.Column(db.Date, nullable=False)

class Purchases(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vendor = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Float, nullable=False)

class Purchase_Detail(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    purchase = db.Column(db.Integer, nullable=False)
    item = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String)
    email = db.Column(db.String)
    password = db.Column(db.String)
    
db.create_all()


def vendor_list():
    vendors_list = db.session.query(Vendors).all()
    vendors = [(vendor.id, vendor.name) for vendor in vendors_list]
    return vendors

class ItemsForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    description = StringField('Descripcion', validators=[DataRequired()])
    vendor = SelectField('Proveedor', choices=vendor_list())
    date_purchase = DateField('Fecha de compra', validators=[DataRequired()])
    submit = SubmitField('Guardar')

class VendorsForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    url = StringField('Sitio web', validators=[URL()])
    submit = SubmitField('Agregar')
    
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Let me in')
    
class RegisterForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')
    
    

nav = Nav()

@nav.navigation()
def mynavbar():
    return Navbar(
        'Insumos',
        View('Inicio', 'home'),
        View('Listar articulos','items_list'),
        View('Agregar Articulos','items'),
        View('Agregar Proveedores','vendors'),
        View('Logout','logout')
    )
    
@nav.navigation()
def mynavbar_not_login():
    return Navbar(
        'Insumos',
        View('Login','login'),
        View('Logout','logout')
    )

nav.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

@app.route('/')
@login_required
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data 
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
                
            else:
                flash("Password not match")
        else:
            flash("User not found")
    return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
@login_required
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name  = form.name.data
        email = form.email.data
        password = form.password.data
        secure_password  = generate_password_hash(password, 'pbkdf2:sha256', 8)
        new_user = User(name=name, email=email, password=secure_password)
        db.session.add(new_user)
        db.session.commit()
        
    return render_template('register.html', form=form)

@app.route('/items-list')
@login_required
def items_list():
    items = db.session.query(Items).all()
    return render_template('items-list.html',items=items)

@app.route('/items', methods=['GET','POST'])
@login_required
def items():
    form = ItemsForm()
    form.vendor.choices = vendor_list()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        vendor = int(form.vendor.data)
        date_purchase = form.date_purchase.data
        new_item = Items(name=name, description=description, quantity=0, vendor=vendor, date_purchase=date_purchase)
        db.session.add(new_item)
        db.session.commit()
        flash('Los datos fueron guardados exitosamente.')
        return redirect(url_for('items'))
    return render_template('items.html', form=form)

@app.route('/vendors', methods=['GET','POST'])
@login_required
def vendors():
    form = VendorsForm()
    if form.validate_on_submit():
        name = form.name.data
        url = form.url.data
        new_vendor = Vendors(name=name, site=url)
        db.session.add(new_vendor)
        db.session.commit()
        flash('Los datos fueron guardados exitosamente.')
        return redirect(url_for('vendors'))

    return render_template('vendors.html', form=form)



if __name__ == "__main__":
    app.run(debug=True, port=5001)