# is REST-auth/blob/master/api.py

import os
from flask import Flask, abort, request, jsonify, g, url_for

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

#initialization
app = Flask (__name__)
app.config['SECRET_KEY'] = 'abra kadabra'

#extensions 
auth = HTTPBasicAuth()


users = {
    "opay": generate_password_hash("opay"),
    "viada": generate_password_hash("viada")
}

def generate_auth_token(user, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        s.dumps({'id': 1})
        return s.dumps({'user': user})

@auth.verify_password
def verify_pwd(username, password):
  if username in users:
      return check_password_hash(users.get(username), password)
  return False 


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = generate_auth_token(auth.username(), 600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')