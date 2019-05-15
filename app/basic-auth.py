from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask (__name__)

auth = HTTPBasicAuth()

users = {
 "opay": generate_password_hash("opay"),
 "viada": generate_password_hash("viada")
}

@auth.verify_password
def verify_pwd(username, password):
  if username in users:
      return check_password_hash(users.get(username), password)
  return False 


@app.route('/login')
@auth.login_required
def login():
    return "Hello, %s !" % auth.username()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')