
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

def get_user(client_id):
    """
    Return a user.
    This endpoint is publicly available, but if the client has a token it
    should send it, as that indicates to the server that the user is online.
    """
    if client_id in users:
      return  True
    return False 


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