import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_

app = Flask(__name__)

app.config['SECRET_KEY'] = 'chemi_saidumlo_key_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///releaf_super_final.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    products = db.relationship('Product', backref='owner', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField('მომხმარებლის სახელი', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('პაროლი', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('გაიმეორეთ პაროლი', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('რეგისტრაცია')


class LoginForm(FlaskForm):
    username = StringField('მომხმარებლის სახელი', validators=[DataRequired()])
    password = PasswordField('პაროლი', validators=[DataRequired()])
    submit = SubmitField('შესვლა')


class ProductForm(FlaskForm):
    title = StringField('ნივთის სახელი', validators=[DataRequired()])
    description = TextAreaField('აღწერა', validators=[DataRequired()])
    price = FloatField('ფასი (₾)', validators=[DataRequired()])
    category = SelectField('კატეგორია', choices=[
        ('tech', 'ტექნიკა '),
        ('furniture', 'ავეჯი '),
        ('clothing', 'ტანსაცმელი '),
        ('books', 'წიგნები '),
        ('other', 'სხვადასხვა ')
    ], validators=[DataRequired()])
    image = FileField('ნივთის სურათი', validators=[
        FileRequired(message='გთხოვთ, ატვირთოთ სურათი!'),
        FileAllowed(['jpg', 'png', 'jpeg', 'webp', 'gif', 'bmp'], 'დაშვებულია სურათები: jpg, png, webp, gif!')
    ])
    submit = SubmitField('დამატება')


@app.context_processor
def inject_cart_count():
    cart = session.get('cart', [])
    return dict(cart_count=len(cart))


@app.route('/')
def home():
    q = request.args.get('q')
    if q:
        approved_products = Product.query.filter(
            Product.status == 'approved',
            or_(Product.title.contains(q), Product.description.contains(q))
        ).all()
    else:
        approved_products = Product.query.filter_by(status='approved').all()

    is_admin_view = False
    if current_user.is_authenticated and current_user.is_admin:
        is_admin_view = True
    return render_template('home.html', products=approved_products, is_admin_view=is_admin_view)


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'cart' not in session:
        session['cart'] = []
    cart = session['cart']
    cart.append(product_id)
    session['cart'] = cart
    flash('ნივთი დაემატა კალათაში! 🛒')
    return redirect(request.referrer or url_for('home'))


@app.route('/cart')
def view_cart():
    cart_ids = session.get('cart', [])
    products = []
    total_price = 0
    for p_id in cart_ids:
        product = Product.query.get(p_id)
        if product:
            products.append(product)
            total_price += product.price
    return render_template('cart.html', products=products, total=total_price)


@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', [])
    if product_id in cart:
        cart.remove(product_id)
        session['cart'] = cart
        flash('ნივთი ამოღებულია კალათიდან 🗑')
    return redirect(url_for('view_cart'))


@app.route('/clear_cart')
def clear_cart():
    session.pop('cart', None)
    flash('კალათა გასუფთავდა ️')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('ეს სახელი უკვე დაკავებულია ')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(form.password.data)
        existing_users_count = User.query.count()
        is_admin_user = (existing_users_count == 0)

        new_user = User(username=form.username.data, password=hashed_pw, is_admin=is_admin_user)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('რეგისტრაცია წარმატებულია!')
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('წარმატებული შესვლა! ')
            return redirect(url_for('home'))
        else:
            flash('პაროლი ან სახელი არასწორია ')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('თქვენ გახვედით სისტემიდან ')
    return redirect(url_for('login'))


@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        f = form.image.data
        filename = secure_filename(f.filename)
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_prod = Product(
            title=form.title.data, description=form.description.data,
            price=form.price.data, category=form.category.data,
            image=filename, user_id=current_user.id, status='pending'
        )
        db.session.add(new_prod)
        db.session.commit()
        flash('ნივთი დამატებულია! ელოდება ადმინის დასტურს ')
        return redirect(url_for('home'))
    return render_template('add_product.html', form=form)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("შენ არ ხარ ადმინი! ")
        return redirect(url_for('home'))
    pending_products = Product.query.filter_by(status='pending').all()
    return render_template('admin.html', products=pending_products)


@app.route('/approve/<int:product_id>')
@login_required
def approve(product_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    product.status = 'approved'
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/reject/<int:product_id>')
@login_required
def reject(product_id):
    if not current_user.is_admin: return redirect(url_for('home'))
    product = Product.query.get_or_404(product_id)
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image)
        if os.path.exists(file_path): os.remove(file_path)
    except:
        pass
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('admin'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists('static/uploads'):
            os.makedirs('static/uploads')
    app.run(debug=True)