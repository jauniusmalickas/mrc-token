
import os
from flask import Flask, current_app, abort, request, jsonify, g, url_for


from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash


#initialization
app = Flask (__name__)
app.config['SECRET_KEY'] = 'abra kadabra'

#extensions 
auth = HTTPBasicAuth()

users = {
    "opay": generate_password_hash("opay"),
    "viada": generate_password_hash("viada")
}

def isUser(client_id):
    """
    Return true if  user is in db.
    """
    if client_id in users:
      return  True
    return False 

def getUser(client_id):
    """
    Return user.
    """
    if client_id in users:
      return users.get(client_id)

@auth.verify_password
def verify_pwd(client_id, secret):
  if client_id in users:
      return check_password_hash(users.get(client_id), secret)
  return False 



@auth.error_handler
def password_error():
    """Return a 401 error to the client."""
    # To avoid login prompts in the browser, use the "Bearer" realm.
    return (jsonify({'error': 'authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')