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
        
        return f(*args, **kwargs)
    return decorated

#rota protegida (somente acessível com token válido)
@app.route('/register',methods=['GET'])
@token_requerido
def rota_protegida():
    return jsonify({"mensagem":"Acesso permitido","userid":request.userid})

#endpoint para criar um novo usuário com senha (CREATE)
#http://localhost:5000/register
@app.route('/register',methods=['POST'])
def register_user ():
    data = request.get_json()
    username = data.get('username')
    email = data.get ('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error':'username, email,password are required'})#,400
    
    #hash da senha antes de salvar no banco de dados
    hashed_password = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO users(username,email,password)VALUES (?,?,?)', 
                   (username,email,hashed_password))
    db.commit()
    return jsonify ({'id':cursor.lastrowid,'username':username,'email':email})

#endpoint de login que gera e retorna um token  de acesso (LOGIN)
@app.route('/login',methods=['POST'])
def login():
     data = request.get_json()
     username = data.get('username')
     password = data.get('password')

     if not username or not password:
          return jsonify({'error':'usuario e senha é requerido'})
     
     bd = get_db()
     cursor = bd.cursor()
     cursor.execute('SELECTE *FROM users where username = ?',(username,))
     user = cursor.fetchone()

     #print (user[0],user[1])

     if user is None or not check_password_hash(user[3],password):
          return jsonify({'error':'usuario ou senha incorreto'}),


    #se o login for bvem-sucedido,gera um token JWT
    token = generate_token(username,user[0])

    return jsonify({'mensage':'login sucesso','token':token})


#fecha a conexão com o banco de dados ao finalizar a requisição
@app.teardown_appcontext
def close_connection(exception):
     db=getattr(g,'_database',None)
     if db is not None:
        db.close()

if _name_=='_main_':
     init_db()#Inicializar o banco de dados ao iniciar o app
     app.run(debug=True)
