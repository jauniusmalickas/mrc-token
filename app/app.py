from flask import Flask, jsonify, current_app, g, request, abort
from flask_expects_json import expects_json
from token_auth import  generate_token, token_auth
from basic_auth import auth, isUser, getUser

app = Flask(__name__)

app.config['SECRET_KEY'] = 'abra kadabra'

checkin = {
    'type': 'object',
    'properties': {
        'mgOperationId': {'type': 'string'},
        'spotId': {'type': 'string'},
        'languageId': {'type': 'string'},
        'loyaltyId' : {'type': 'string'},
        'loyaltyNumber': {'type': 'string'}
    },
    'required': ['mgOperationId', 'spotId']
}


def to_dict (client_id): 
    response = {}
    if client_id == 'opay':
        response = {
            'errorCode': 0, 'mgOperationId': g.data['mgOperationId'], 'mode': 1,  'modeName' : 'ServiceFirst', 'checkinLifetime': 10}
    if client_id == 'viada':
        response = {
            'errorCode': 0, 'mgOperationId': g.data['mgOperationId'], 'mode': 2,  'modeName' : 'PayFirst', 'checkinLifetime': 10}
    
    return response


@app.before_request
def before_request():
    
    if request.authorization:
        g.user = request.authorization['username']
        print('basic auth -> user %', g.user)
    
        data = request.form
        if data.get('grant_type') != 'client_credentials':
            abort(403)

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
@expects_json(checkin)
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
    
    print('g.data ->  s%', g.data)
    
    if not isUser(g.jwt_claims['client_id']):
        abort(403)
    client_id = g.jwt_claims['client_id']
        
    r = jsonify(to_dict(client_id))
    r.status_code = 202
    
    return r


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
