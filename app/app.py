from flask import Flask, jsonify, current_app, g, request
from token_auth import  generate_token, token_auth
from basic_auth import auth, get_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'abra kadabra'


@app.before_request
def before_request():
    
    if request.authorization:
        g.user = request.authorization['username']
        print('basic auth -> user %', g.user)
    
    if hasattr(g, 'jwt_claims') and 'client_id' in g.jwt_claims:
        g.user = g.jwt_claims['client_id']
        print('token auth -> user %', g.user)
        if g.user is None:
            abort(500)
        

@app.route('/api', methods=['GET', 'POST'])
@auth.login_required
def my_microservice():
    return jsonify({'Hello': 'World!'})


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
    print("The raw Authorization header")
    print(request.environ["HTTP_AUTHORIZATION"])
    print("Flask's Authorization header")
    print(request.authorization)
   
    
    print('token auth -> user %', g.jwt_claims['client_id'])
     #tbd padaryti metoda getUser is token client_id
   
    
    if not get_user(g.jwt_claims['client_id']):
        abort(403)
   
    return jsonify({'client_id': g.jwt_claims['client_id'], 'payment_type':1, 'timeout': 600}), 201




if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
