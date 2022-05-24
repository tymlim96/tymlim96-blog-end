from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

# BASIC APP SETUP WITH CKEDITOR (FORM FIELD) AND FLASK BOOTSTRAP
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "alternate_secret_key")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
uri = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
# Workaround to replace start of DATABASE_URL with updated start
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CONFIGURE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# Initialize Gravatar with app
gravatar = Gravatar(
    app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


# User loader for login manager (loads up User based on user_id provided in session)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CONFIGURE TABLES
# User table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


# Blog Post Table
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer)
    author = relationship("User", back_populates="posts")

    # Comments table relationship (BlogPost table is parent)
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# Comment table
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer)
    comment_author = relationship("User", back_populates="comments")
    # Relationship with BlogPost table (BlogPost table is parent)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


# ADMIN ONLY DECORATOR
def admin_only(function):
    # Wrapping to take original function's attributes using functools' wraps
    @wraps(function)
    def decorated_function(*args, **kwargs):
        try:
            # Check if NOT admin
            if current_user.id != 1:
                # Return 403 error
                return abort(403)
        # If NOT logged in, there is not "id" attribute
        except AttributeError:
            return abort(403)
        else:
            # Return normal function
            return function(*args, **kwargs)

    return decorated_function


# ROUTES
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    # Check if form successfully submitted
    if register_form.validate_on_submit():
        # Check if email entered exists already
        email = register_form.email.data
        if User.query.filter_by(email=email).first():
            # Inform user to login instead
            flash("You have already signed up with that email. Please log in instead.")
            return redirect(url_for("login"))
        else:
            # Create hashed and salted password
            hashed_and_salted_password = generate_password_hash(
                password=register_form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            # Add new user to database
            new_user = User(
                email=email,
                password=hashed_and_salted_password,
                name=register_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            # Login user and redirect to home page
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    # Else, GET the register form page
    else:
        return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Check if email does NOT exist in database
        if not user:
            flash("The email does not exist, please try again.")
            return redirect(url_for("login"))
        # Check if user's password does NOT match database
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))
        # Everything checks out
        else:
            # Login the user
            login_user(user)
            return redirect(url_for("get_all_posts"))
    # Else GET the login form
    else:
        return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    # If comment form submission is valid (this is a POST request)
    if comment_form.validate_on_submit():
        # Check if current user is NOT authenticated (logged in)
        if not current_user.is_authenticated:
            # Redirect to login and prompt user to log in
            flash("Please log in first.")
            return redirect(url_for("login"))

        # Add new comment to database
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        # Redirect to the current post's page
        return redirect(url_for("show_post", post_id=requested_post.id))
    # Else, return the GET request for the post information
    else:
        return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
