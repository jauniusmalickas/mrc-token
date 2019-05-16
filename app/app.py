from flask import Flask, jsonify, current_app,g
from token_auth import  generate_token, token_auth
from basic_auth import auth

app = Flask(__name__)

app.config['SECRET_KEY'] = 'abra kadabra'

@app.route('/api', methods=['GET', 'POST'])
@token_auth.login_required
def my_microservice():
    return jsonify({'Hello': 'World!'})

if __name__ == '__main__':
    app.run()
