import os
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user



#create flask instance
app = Flask(__name__)

# create a Database using SQLlite and SQLAlchemy
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


# Create Database Using MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:nikhil08012004@localhost/our_users'


# Initialize Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Create a DB Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=lambda: datetime.now(pytz.utc))
    password_hash = db.Column(db.String(120))
    

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


    # Create a String 
    def __repr__(self):
        return '<Name %r' % self.username




# create a secret key for using forms
app.config['SECRET_KEY'] = "Nikhil"




# Create a User Form Class
class UserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")


# To Add a User

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    username = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # Hashing the password
            hashed_pw = generate_password_hash(form.password_hash.data, method='pbkdf2:sha256')
            user = Users(username = form.username.data, email = form.email.data, password_hash = hashed_pw)
            db.session.add(user)
            db.session.commit()
        username = form.username.data
        form.username.data = ''
        form.email.data = ''
        form.password_hash = ''
        flash("User Added Successfully !!! ")

    our_users = Users.query.order_by(Users.date_created)
    return render_template("add_user.html", form=form, username = username, our_users = our_users)



# To update the User
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	name_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		name_to_update.username = request.form['username']
		name_to_update.email = request.form['email']		
		try:
			db.session.commit()
			flash("User Updated Successfully!")
			return render_template("dashboard.html", form=form, name_to_update = name_to_update, id=id)
		except:
			flash("Error!  Looks like there was a problem...try again!")
			return render_template("update.html", form=form, name_to_update = name_to_update, id=id)
	else:
		return render_template("update.html", form=form, name_to_update = name_to_update, id = id)


        



# To Delete the User
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)

    username = None
    form = UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        
        flash("User Deleted Successfully!!!")

        our_users = Users.query.order_by(Users.date_created)
        return render_template("add_user.html", form=form, username = username, our_users = our_users)

    except:
        flash("Whoops!!! There was a problem deleting user, Try Again.")
        return render_template("add_user.html", form=form, username = username, our_users = our_users)









# Create a Form Class
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Flask Login Requirements
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Create a Password Form Class
class PasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


# Create a Password Test page
@app.route('/test_pw', methods=['GET','POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None  
    form = PasswordForm()

    #Validate Form
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data

        form.email.data = ''
        form.password_hash.data = ''

        pw_to_check = Users.query.filter_by(email=email).first()

        passed = check_password_hash(pw_to_check.password_hash, password)
        
    return render_template("test_pw.html", email = email, password = password,
                            passed = passed, pw_to_check = pw_to_check, form = form)



# Create a Login page
@app.route('/login', methods=['GET','POST'])
def login():
    username = None
    form = LoginForm()
    #Validate Form
    if form.validate_on_submit():
        user = Users.query.filter_by(username = form.username.data).first()
        if user:
            # Check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Successful")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password - Try Again!")
        else:
            flash("Username Doesn't exist! Try Again...")
                
    return render_template("login.html", username = username, form = form)



# Create Logout function
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You have been Logged Out !!!")
    return redirect((url_for('login')))




# Create a Dashboard Page
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():           
    return render_template("dashboard.html")



# create a route decorator
@app.route('/')
@login_required
def index():
    return render_template("index.html")

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Internal Sever Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500






# Create a Posts Model
class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(255))
	content = db.Column(db.Text)
	author = db.Column(db.String(255))
	date_posted = db.Column(db.DateTime, default=lambda: datetime.now(pytz.utc))
	slug = db.Column(db.String(255))
	# Foreign Key To Link Users (refer to primary key of the user)
	#poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


# Create a Posts Form
class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = StringField("Content", validators=[DataRequired()], widget=TextArea())
	#content = CKEditorField('Content', validators=[DataRequired()])
	
	author = StringField("Author")
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")
   


# Add Post Page
@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():
		post = Posts(title=form.title.data, content=form.content.data, author = form.author.data, slug=form.slug.data)
		# Clear The Form
		form.title.data = ''
		form.content.data = ''
		form.author.data = ''
		form.slug.data = ''

		# Add post data to database
		db.session.add(post)
		db.session.commit()

		# Return a Message
		flash("Blog Post Submitted Successfully!")

	# Redirect to the webpage
	return render_template("add_post.html", form=form)





# Edit Blog Posts
@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data 

        # update database
        db.session.add(post)
        db.session.commit()
        flash("Post has been updated")
        return redirect(url_for('post', id=post.id)) 
    
    form.title.data = post.title
    form.author.data = post.author
    form.slug.data = post.slug
    form.content.data = post.content
    return render_template('edit_post.html', form=form)
          	 
   
    
	
# Delete the post
@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    try:
        db.session.delete(post_to_delete)
        db.session.commit()

        # Return a message
        flash("Blog Post Was Deleted!")

        # Grab all the posts from the database
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)


    except:
        # Return an error message
        flash("Whoops! There was a problem deleting post, try again...")

        # Grab all the posts from the database
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)
	




@app.route('/posts')
def posts():
	# Grab all the posts from the database
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template("posts.html", posts=posts)
    

@app.route('/posts/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	return render_template('post.html', post=post)





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)