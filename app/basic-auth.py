# is REST-auth/blob/master/api.py

import os
from flask import Flask, current_app, abort, request, jsonify, g, url_for
import yaml  #kol kas nenaudojame 
import jwt



from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from datetime import datetime, timedelta

#initialization
app = Flask (__name__)
app.config['SECRET_KEY'] = 'abra kadabra'

#extensions 
auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')

users = {
    "opay": generate_password_hash("opay"),
    "viada": generate_password_hash("viada")
}


@app.before_request
def before_request():
    if hasattr(g, 'jwt_claims') and 'client_id' in g.jwt_claims:
        g.user = g.jwt_claims['client_id']
        print('user %s', g.user)
        if g.user is None:
            abort(500)
    
    if request.authorization:
        g.user = request.authorization['username']
    else:
        g.user = 'Anonymous'


@auth.verify_password
def verify_pwd(client_id, secret):
  if client_id in users:
      return check_password_hash(users.get(client_id), secret)
  return False 

def generate_token(client_id, expires_in=60):
    """Generate a JWT token.
    :param user_id the user that will own the token
    :param expires_on expiration time in seconds
    """
    secret_key = current_app.config['SECRET_KEY']
    return jwt.encode(
        {'client_id': client_id,
         'exp': datetime.utcnow() + timedelta(seconds=expires_in)},
        secret_key, algorithm='HS256').decode('utf-8')

@token_auth.verify_token
def verify_token(token):
    """Token verification callback."""

    # this inner function checks if a token appears in the revoked token list
    # the ttl_cache decorator from the cachetools package saves the revoked
    # status for a token for one minute, to avoid lots of duplicated calls to
    # the etcd service.
      
    secret_key = current_app.config['SECRET_KEY']
    g.jwt_claims = {}
    try:
        g.jwt_claims = jwt.decode(token, secret_key, algorithms=['HS256'])
        print('user: %', g.jwt_claims)
    except:
        # we really don't care what is the error here, any tokens that do not
        # pass validation are rejected
        return False
    return True



@app.route('/v1/oauth2/requestToken', methods=['POST', 'GET'])
@auth.login_required
def get_auth_token():
    token = generate_token(g.user, 600)
    return jsonify({'access_token': token, 'token_type':'Bearer', 'expires_in': 600}), 201


@app.route('/v1/submitCheckin', methods=['POST'])
@token_auth.login_required
def submitCheckin():
    """
    Modify an existing user.
    This endpoint requires a valid user token.
    Note: users are only allowed to modify themselves.
    """
    if g.jwt_claims['client_id'] not in users:
        abort(403)
   
    return '', 204

@auth.error_handler
def password_error():
    """Return a 401 error to the client."""
    # To avoid login prompts in the browser, use the "Bearer" realm.
    return (jsonify({'error': 'authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})

@token_auth.error_handler
def token_error():
    """Return a 401 error to the client."""
    return (jsonify({'error': 'token authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')