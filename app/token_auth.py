"""Common authentication functions.
This module contains functions to generate and verify JWT tokens.
"""
from datetime import datetime, timedelta

from flask import current_app, g, jsonify
from flask_httpauth import HTTPTokenAuth
import jwt


token_auth = HTTPTokenAuth('Bearer')

# generate oauth2 JWT accessToken 
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

#verify provided accessToken
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


@token_auth.error_handler
def token_error():
    """Return a 401 error to the client."""
    return (jsonify({'error': 'authentication required'}), 401,
            {'WWW-Authenticate': 'Bearer realm="Authentication Required"'})



