from flask import Flask, render_template, request, redirect, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ums.sqlite"
app.config["SECRET_KEY"] = "6afb1e7cbf0fccc265b37ebc"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'User("{self.username}", "{self.email}", "{self.password}")'

# Main index route
@app.route('/')
def Index():
    return render_template('index.html', title="")

# User login
@app.route('/user/')
def userindex():
    return render_template('user/index.html',title="User login")













# admin login
@app.route('/admin/')
def adminindex():
    return render_template('admin/index.html', title ="admin login")

# User registration 
@app.route('/user/signup', methods=['POST', 'GET'])
def userSignup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()

        if username == "" or email == "" or password == "":
            flash('Please fill in all the necessary details')
            return redirect('/user/signup')
        elif user_exists:
            flash('Username already exists')
            return redirect('/user/signup')
        elif email_exists:
            flash('Email already exists')
            return redirect('/user/signup')
        else:
            hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hash_password)
            print (user)
            
            db.session.add(user)
            db.session.commit()
            flash('User registration done')
            return redirect('/user/')

    return render_template('user/signup.html', title="User Sign-Up")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
app.run(debug=True)
