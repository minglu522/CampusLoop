import os, sqlite3, secrets, hmac
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "campusloop.db"
UPLOAD_DIR = BASE / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED = {"png", "jpg", "jpeg", "webp"}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            condition TEXT NOT NULL,
            campus TEXT NOT NULL,
            image TEXT,
            status TEXT NOT NULL DEFAULT 'available',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS favorites (
            user_id INTEGER NOT NULL REFERENCES users(id),
            product_id INTEGER NOT NULL REFERENCES products(id),
            PRIMARY KEY(user_id, product_id)
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL REFERENCES products(id),
            buyer_id INTEGER NOT NULL REFERENCES users(id),
            seller_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        count = c.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0:
            demo_hash = generate_password_hash("campus123")
            c.execute("INSERT OR IGNORE INTO users(username,password_hash) VALUES(?,?)", ("demo", demo_hash))
            uid = c.execute("SELECT id FROM users WHERE username='demo'").fetchone()[0]
            samples = [
                ("大学英语教材", "九成新，适合本学期学习使用，支持校内自提。", "教材书籍", 18, "九成新", "示范校区"),
                ("无线蓝牙耳机", "功能正常，配件齐全，购买前可当面检查。", "数码产品", 45, "八成新", "示范校区"),
                ("宿舍台灯", "光线柔和，三档亮度，毕业整理转出。", "生活用品", 22, "九成新", "示范校区"),
                ("双肩背包", "日常使用痕迹轻微，容量充足。", "服饰箱包", 30, "八成新", "示范校区"),
            ]
            c.executemany("""INSERT INTO products(user_id,title,description,category,price,condition,campus)
                             VALUES(?,?,?,?,?,?,?)""", [(uid,*x) for x in samples])

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]

@app.context_processor
def inject_globals():
    return {"current_user": session.get("user"), "csrf_token": csrf_token}

@app.before_request
def protect_post():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not sent or not expected or not hmac.compare_digest(sent, expected):
            abort(400, "表单验证失败，请刷新页面后重试。")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("请先登录后再操作。", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    campus = request.args.get("campus", "").strip()
    sql = """SELECT p.*, u.username seller FROM products p JOIN users u ON p.user_id=u.id
             WHERE p.status='available'"""
    args = []
    if q:
        sql += " AND (p.title LIKE ? OR p.description LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND p.category=?"
        args.append(category)
    if campus:
        sql += " AND p.campus LIKE ?"
        args.append(f"%{campus}%")
    sql += " ORDER BY p.created_at DESC"
    with db() as c:
        products = c.execute(sql, args).fetchall()
    return render_template("index.html", products=products, q=q, category=category, campus=campus)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 2 or len(username) > 24 or len(password) < 8:
            flash("用户名需为2-24位，密码至少8位。", "error")
        else:
            try:
                with db() as c:
                    c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                              (username, generate_password_hash(password)))
                flash("注册成功，请登录。", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("用户名已存在，请换一个。", "error")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as c:
            user = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user"] = user["username"]
            flash("登录成功，欢迎回来！", "success")
            return redirect(url_for("index"))
        flash("用户名或密码不正确。", "error")
    return render_template("auth.html", mode="login")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("已退出登录。", "success")
    return redirect(url_for("index"))

@app.route("/publish", methods=["GET", "POST"])
@login_required
def publish():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        desc = request.form.get("description", "").strip()
        category = request.form.get("category", "")
        campus = request.form.get("campus", "").strip()
        condition = request.form.get("condition", "")
        try:
            price = float(request.form.get("price", ""))
        except ValueError:
            price = -1
        if not title or not desc or not campus or price < 0 or price > 100000:
            flash("请完整填写信息，价格需在0至100000元之间。", "error")
            return render_template("publish.html")
        image_name = None
        f = request.files.get("image")
        if f and f.filename:
            safe = secure_filename(f.filename)
            ext = safe.rsplit(".", 1)[-1].lower() if "." in safe else ""
            if ext not in ALLOWED:
                flash("图片仅支持 PNG、JPG、JPEG、WEBP 格式。", "error")
                return render_template("publish.html")
            image_name = secrets.token_hex(12) + "." + ext
            f.save(UPLOAD_DIR / image_name)
        with db() as c:
            c.execute("""INSERT INTO products(user_id,title,description,category,price,condition,campus,image)
                         VALUES(?,?,?,?,?,?,?,?)""",
                      (session["user_id"], title, desc, category, price, condition, campus, image_name))
        flash("商品发布成功！", "success")
        return redirect(url_for("index"))
    return render_template("publish.html")

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route("/product/<int:product_id>")
def product_detail(product_id):
    with db() as c:
        p = c.execute("""SELECT p.*,u.username seller FROM products p JOIN users u ON p.user_id=u.id
                         WHERE p.id=?""", (product_id,)).fetchone()
    if not p:
        abort(404)
    favorited = False
    if session.get("user_id"):
        with db() as c:
            favorited = bool(c.execute("SELECT 1 FROM favorites WHERE user_id=? AND product_id=?",
                                       (session["user_id"], product_id)).fetchone())
    return render_template("detail.html", p=p, favorited=favorited)

@app.route("/favorite/<int:product_id>", methods=["POST"])
@login_required
def favorite(product_id):
    with db() as c:
        exists = c.execute("SELECT 1 FROM favorites WHERE user_id=? AND product_id=?",
                           (session["user_id"], product_id)).fetchone()
        if exists:
            c.execute("DELETE FROM favorites WHERE user_id=? AND product_id=?", (session["user_id"], product_id))
            flash("已取消收藏。", "success")
        else:
            c.execute("INSERT OR IGNORE INTO favorites(user_id,product_id) VALUES(?,?)",
                      (session["user_id"], product_id))
            flash("已加入收藏。", "success")
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/interest/<int:product_id>", methods=["POST"])
@login_required
def interest(product_id):
    message = request.form.get("message", "").strip()[:300]
    with db() as c:
        p = c.execute("SELECT * FROM products WHERE id=? AND status='available'", (product_id,)).fetchone()
        if not p:
            abort(404)
        if p["user_id"] == session["user_id"]:
            flash("不能向自己发布的商品发起购买意向。", "warning")
        else:
            c.execute("INSERT INTO orders(product_id,buyer_id,seller_id,message) VALUES(?,?,?,?)",
                      (product_id, session["user_id"], p["user_id"], message))
            flash("购买意向已提交，请通过安全的校内方式联系卖家确认。", "success")
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/me")
@login_required
def me():
    with db() as c:
        listings = c.execute("SELECT * FROM products WHERE user_id=? ORDER BY created_at DESC",
                             (session["user_id"],)).fetchall()
        orders = c.execute("""SELECT o.*,p.title,p.price,u.username buyer FROM orders o
                              JOIN products p ON o.product_id=p.id JOIN users u ON o.buyer_id=u.id
                              WHERE o.seller_id=? ORDER BY o.created_at DESC""",
                           (session["user_id"],)).fetchall()
        favorites = c.execute("""SELECT p.* FROM favorites f JOIN products p ON f.product_id=p.id
                                 WHERE f.user_id=? ORDER BY p.created_at DESC""",
                              (session["user_id"],)).fetchall()
    return render_template("me.html", listings=listings, orders=orders, favorites=favorites)

@app.route("/order/<int:order_id>/status", methods=["POST"])
@login_required
def order_status(order_id):
    status = request.form.get("status")
    if status not in {"accepted", "completed", "cancelled"}:
        abort(400)
    with db() as c:
        order = c.execute("SELECT * FROM orders WHERE id=? AND seller_id=?",
                          (order_id, session["user_id"])).fetchone()
        if not order:
            abort(404)
        c.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
        if status == "completed":
            c.execute("UPDATE products SET status='sold' WHERE id=?", (order["product_id"],))
    flash("交易状态已更新。", "success")
    return redirect(url_for("me"))

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=str(e)), 400

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="没有找到你要访问的内容。"), 404

init_db()

if __name__ == "__main__":
    app.run(debug=True)
