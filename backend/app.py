
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
import sqlite3, os, hashlib, hmac, secrets, time
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(__file__)
DB = os.path.join(BASE, "mines.db")
SERVER_SEED = os.path.join(BASE, "server_seed.txt")

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'change-this-secret'
CORS(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

def get_conn():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = get_conn().cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, balance REAL DEFAULT 1000, is_admin INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS games (id INTEGER PRIMARY KEY, user_id INTEGER, bet REAL, mines INTEGER, client_seed TEXT, server_seed TEXT, result TEXT, profit REAL, timestamp TEXT)""")
    get_conn().commit()

def ensure_server_seed():
    if not os.path.exists(SERVER_SEED):
        with open(SERVER_SEED, "w") as f:
            f.write(secrets.token_hex(32))

def server_hash():
    ensure_server_seed()
    with open(SERVER_SEED) as f: return hashlib.sha256(f.read().strip().encode()).hexdigest()

def reveal_seed():
    with open(SERVER_SEED) as f: return f.read().strip()

def gen_positions(server_seed, client_seed, mines, grid=25):
    digest = hmac.new(server_seed.encode(), client_seed.encode(), hashlib.sha256).hexdigest()
    positions = set(); i=0
    while len(positions) < mines:
        chunk = digest[i*8:(i+1)*8]
        if not chunk:
            digest = hashlib.sha256(digest.encode()).hexdigest(); i=0; continue
        positions.add(int(chunk,16) % grid); i+=1
    return sorted(list(positions))

@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json or {}; u=data.get('username'); p=data.get('password')
    if not u or not p: return jsonify({'error':'username/password required'}),400
    pw=generate_password_hash(p)
    try:
        c=get_conn().cursor(); c.execute("INSERT INTO users (username,password) VALUES (?,?)",(u,pw)); get_conn().commit(); return jsonify({'message':'ok'})
    except Exception as e:
        return jsonify({'error':'username exists'}),400

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}; u=data.get('username'); p=data.get('password')
    if not u or not p: return jsonify({'error':'username/password required'}),400
    c=get_conn().cursor(); c.execute("SELECT id,password,balance,is_admin FROM users WHERE username=?",(u,)); row=c.fetchone()
    if not row or not check_password_hash(row['password'], p): return jsonify({'error':'invalid'}),401
    token=create_access_token(identity={'user_id':row['id'],'is_admin':row['is_admin']})
    return jsonify({'access_token':token,'user_id':row['id'],'balance':row['balance']})

@app.route('/fair/hash', methods=['GET'])
def fair_hash(): return jsonify({'server_hash': server_hash()})

@app.route('/fair/play', methods=['POST'])
@jwt_required()
def fair_play():
    data = request.json or {}; client_seed=data.get('client_seed'); mines=int(data.get('mines',3)); bet=float(data.get('bet',0))
    if not client_seed or bet<=0: return jsonify({'error':'client_seed and bet required'}),400
    ensure_server_seed(); s=reveal_seed(); positions=gen_positions(s, client_seed, mines)
    return jsonify({'mine_positions':positions})

@app.route('/game/record', methods=['POST'])
@jwt_required()
def record():
    ident=get_jwt_identity(); uid=ident['user_id']
    data=request.json or {}; bet=float(data.get('bet',0)); mines=int(data.get('mines',0)); client_seed=data.get('client_seed',''); server_seed=data.get('server_seed',''); result=data.get('result','loss'); profit=float(data.get('profit',0))
    conn=get_conn(); c=conn.cursor(); c.execute("SELECT balance FROM users WHERE id=?", (uid,)); row=c.fetchone()
    if not row: return jsonify({'error':'user not found'}),404
    balance=row['balance']; new_balance = balance + profit if result=='win' else balance - bet
    if new_balance < 0: return jsonify({'error':'insufficient'}),400
    c.execute("UPDATE users SET balance=? WHERE id=?",(new_balance,uid))
    c.execute("INSERT INTO games (user_id,bet,mines,client_seed,server_seed,result,profit,timestamp) VALUES (?,?,?,?,?,?,?,?)",(uid,bet,mines,client_seed,server_seed,result,profit,time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit(); conn.close()
    socketio.emit('leaderboard_update', {}, broadcast=True)
    return jsonify({'message':'recorded','new_balance':new_balance})

@app.route('/history', methods=['GET'])
@jwt_required()
def history():
    uid=get_jwt_identity()['user_id']; c=get_conn().cursor(); c.execute("SELECT id,bet,mines,result,profit,timestamp FROM games WHERE user_id=? ORDER BY id DESC LIMIT 50",(uid,)); rows=c.fetchall(); return jsonify([dict(r) for r in rows])

@app.route('/leaderboard', methods=['GET'])
def leaderboard(): c=get_conn().cursor(); c.execute("SELECT username,balance FROM users ORDER BY balance DESC LIMIT 10"); rows=c.fetchall(); return jsonify([dict(r) for r in rows])

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def admin_users():
    if not get_jwt_identity().get('is_admin'): return jsonify({'error':'admin only'}),403
    c=get_conn().cursor(); c.execute("SELECT id,username,balance,is_admin FROM users"); rows=c.fetchall(); return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    init_db(); ensure_server_seed(); socketio.run(app, host='0.0.0.0', port=5000)
