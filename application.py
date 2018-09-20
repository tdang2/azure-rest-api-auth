from flask import Flask, Response, session, request, redirect, abort, render_template
import requests
import uuid
import adal
import os
from dotenv import load_dotenv


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET')

PORT = os.getenv('PORT')  # A flask app by default runs on PORT 5000
AUTHORITY_URL = os.getenv('AUTHORITY_URL')  # format: https://login.microsoftonline.com/ + <azure AD directory_id>
REDIRECT_URI = 'http://localhost:{}/getAToken'.format(PORT)
TEMPLATE_AUTHZ_URL = ('https://login.microsoftonline.com/{}/oauth2/authorize?' +
                      'response_type=code&client_id={}&redirect_uri={}&' +
                      'state={}&resource={}')
RESOURCE = "https://datalake.azure.net/"


@app.route("/hello_world")
def main():
    login_url = 'http://localhost:{}/login'.format(PORT)
    resp = Response(status=307)
    resp.headers['location'] = login_url
    return resp


@app.route("/login")
def login():
    # When testing on url be careful of reserved characters for url format. Convert them to %hex format
    if 'client_id' in request.args and 'password' in request.args:
        auth_state = str(uuid.uuid4())
        session['state'] = auth_state
        session['client_id'] = request.args['client_id']
        session['password'] = request.args['password']
        authorization_url = TEMPLATE_AUTHZ_URL.format(
            "b101f7ab-56ac-485f-b397-5279698fdf7d",
            request.args['client_id'],
            REDIRECT_URI,
            auth_state,
            RESOURCE
        )
        resp = Response(status=307)
        resp.headers['location'] = authorization_url
        return resp
    else:
        abort(400, 'Need login information!')


@app.route("/getAToken")
def main_login():
    code = request.args['code']
    state = request.args['state']
    if state != session['state']:
        raise ValueError("State does not match")
    auth_context = adal.AuthenticationContext(AUTHORITY_URL)
    token_response = auth_context.acquire_token_with_authorization_code(
        code,
        REDIRECT_URI,
        RESOURCE,
        session.get('client_id'),
        session.get('password')
    )
    # It is recommended to save this to a database when using a production app.
    session['access_token'] = token_response['accessToken']
    return redirect('/')


@app.route("/list_folders")
def list_folders():
    if 'access_token' in session:
        endpoint = "https://staplessupplychain.azuredatalakestore.net/webhdfs/v1/?op=LISTSTATUS"
        http_headers = {'Authorization': 'Bearer ' + session.get('access_token'),
                        'User-Agent': 'ad-auth-app',
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'client-request-id': str(uuid.uuid4())}
        data = requests.get(endpoint, headers=http_headers, stream=False).json()
        return render_template('folder_list.html', data=data.get('FileStatuses').get('FileStatus'))
    else:
        abort(401, 'You must log in first')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/')
def hello_world():
    if 'access_token' not in session:
        return 'Hello World no session'
    else:
        return "Hello World! token: {}".format(session['access_token'])


if __name__ == '__main__':
    app.run()
