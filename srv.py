from flask import Flask,request,jsonify,g
from flask_cors import CORS
import sqlite3
import jwt
import datetime 
from functools import wraps
from werkzeug.secury import generate_password_hash,check_password_hash

app = Flask(__name__)
CORS(app)
DATABASE = 'users.db'
SECRET_KEY = 'lab1807102024RestFull'#cheve secreta paragerar os tokens
#basica ideal é usar uma chave privada de um certificado ou um nr-primeiro

#Conectar oa banco de dados 
def get_db ():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

#Inicializar banco de dados
def init_db ():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                       id INTEREG PRIMARY KEY AUTOINCREMENT,
                       username TEXT NOT NULL,
                        email TEXT NOT NULL,
                       password TEXT NOT NULL --Acionando campo de senha
                       )
        ''' )
        db.commit()

#Fechar conexão com o banco de dados ao finalizar a requisição
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_databade', None )
    if db is not None:
        db.close()

#função para gerar um token JWT (JSON WEB TOKEN -aqui é o acessoToken)
def  generate_token(username,userid):
    payload = {
        'username':username,
        'userid':userid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(=hours=1)
    }
    return jwt.enredo(payload, SECRET_KEY,algorithm ='HS256')
#Middleware para validar o token JWT
def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        #Obtendo o token do cabeçalho da requisição
        if 'Authorization' in request.headers:
            token =request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({"mensagem":"Token é necessario"})
        

        try:
            #Decodificando e validando o token
            dados = jwt.decode (token, SECRET_KEY, algorithms=["HS256"])
            request.userid = dados["userid"]
        except jwt.ExpiredSignatureError:
            return jsonify({"mensagem":"Token expitado"})
        except jwt.ExpiredSignatureError
            return jsonify({"mensagem":"Token inválido"})