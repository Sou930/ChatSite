from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Flaskアプリケーション設定
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Userモデル
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # メールアドレス
    is_admin = db.Column(db.Boolean, default=False)  # 管理者フラグ
    comments = db.relationship('Comment', backref='user', lazy=True)

# コメントモデル
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)

# スレッドモデル
class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    comments = db.relationship('Comment', backref='thread', lazy=True)

# インデックスページ
@app.route('/', methods=['GET', 'POST'])
def index():
    threads = Thread.query.all()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_thread = Thread(title=title, content=content)
        db.session.add(new_thread)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('index.html', threads=threads)

# アカウント作成ページ
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        
        if User.query.filter_by(username=username).first():
            return 'そのユーザー名はすでに使われています。'
        
        if User.query.filter_by(email=email).first():
            return 'そのメールアドレスはすでに使われています。'

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('index.html')

# ログインページ
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['is_admin'] = user.is_admin  # 管理者フラグ
            return redirect(url_for('index'))
        return 'ログイン情報が正しくありません。'
    
    return render_template('index.html')

# 管理者専用ページ - ユーザー一覧
@app.route('/admin/users')
def users():
    if 'username' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))  # 管理者以外はリダイレクト

    users = User.query.all()
    return render_template('index.html', users=users)

# スレッド詳細ページ (コメント追加)
@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
def thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)

    if request.method == 'POST':
        content = request.form['content']
        user = User.query.filter_by(username=session['username']).first()
        new_comment = Comment(content=content, user_id=user.id, thread_id=thread.id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('thread', thread_id=thread.id))

    comments = Comment.query.filter_by(thread_id=thread_id).all()
    return render_template('index.html', thread=thread, comments=comments)

if __name__ == '__main__':
    db.create_all()  # データベースの作成
    app.run(debug=True)
