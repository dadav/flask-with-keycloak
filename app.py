#!/usr/bin/env python3

import os
import json
import requests
from functools import wraps
from flask import Flask, session, url_for, render_template, redirect
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebToken, JsonWebKey

app = Flask(__name__)
app.secret_key = 'hunter2'
oauth = OAuth()
oauth.init_app(app)

KEYCLOAK_ISSUER = os.environ.get('KEYCLOAK_ISSUER')
KEYCLOAK_CLIENTID = os.environ.get('KEYCLOAK_CLIENTID')
KEYCLOAK_SECRET = os.environ.get('KEYCLOAK_SECRET')
KEYCLOAK_DISCOVERY_URL = f'{KEYCLOAK_ISSUER}/.well-known/openid-configuration'

oauth.register(
    name='keycloak',
    client_id=KEYCLOAK_CLIENTID,
    client_secret=KEYCLOAK_SECRET,
    server_metadata_url=KEYCLOAK_DISCOVERY_URL,
    client_kwargs={
        'scope': 'openid email profile',
    },
)

def requires_one_of_these_roles(roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'access_token' in session and 'realm_access' in session['access_token'] and 'roles' in session['access_token']['realm_access']:
                for r in session['access_token']['realm_access']['roles']:
                    if r in roles:
                        return func(*args, **kwargs)
            return 'You are not allowed to access this area', 403
        return wrapper
    return decorator

def parse_token(provider, token):
    """https://github.com/batman59/aleph/blob/fdb0ad54ce20ab157b7deaf93773e79b60236d74/aleph/oauth.py#L24="""

    def load_key(header, _):
        jwk_set = JsonWebKey.import_key_set(provider.fetch_jwk_set(force=True))
        return jwk_set.find_by_kid(header.get("kid"))

    metadata = provider.load_server_metadata()
    algs = metadata.get("id_token_signing_alg_values_supported", ["RS256"])
    jwt = JsonWebToken(algs)
    claims = {"exp": {"essential": True}}

    return jwt.decode(token, key=load_key, claims_options=claims)

@app.route('/')
def index():
    id_token = session.get('id_token')
    if id_token is not None:
        id_token = json.dumps(id_token, sort_keys=True, indent=4)
    access_token = session.get('access_token')
    if access_token is not None:
        access_token = json.dumps(access_token, sort_keys=True, indent=4)
    return render_template('index.html', id_token=id_token, access_token=access_token)

@app.route('/login')
def login():
    callback_uri = url_for('callback', _external=True)
    return oauth.keycloak.authorize_redirect(callback_uri)

@app.route('/callback')
def callback():
    token = oauth.keycloak.authorize_access_token()
    id_token = parse_token(oauth.keycloak, token['id_token'])
    access_token = parse_token(oauth.keycloak, token['access_token'])
    refresh_token = token['refresh_token']

    if access_token:
        session['id_token'] = id_token
        session['access_token'] = access_token
        session['refresh_token'] = refresh_token

    return redirect('/')

@app.route('/admin')
@requires_one_of_these_roles(roles=['admin'])
def admin():
    return 'Access granted!'

@app.route('/refresh')
def refresh():
    refresh_token = session.get('refresh_token_plain')

    if refresh_token is None:
        return redirect('/login')

    token_endpoint = f'{KEYCLOAK_ISSUER}/protocol/openid-connect/token'

    resp = requests.post(token_endpoint, data={
        "grant_type": 'refresh_token',
        "client_id": KEYCLOAK_CLIENTID,
        "client_secret": KEYCLOAK_SECRET,
        "refresh_token": refresh_token,
    })
    resp.raise_for_status()
    token = resp.json()
    new_id_token = parse_token(oauth.keycloak, token['id_token'])
    new_access_token = parse_token(oauth.keycloak, token['access_token'])
    new_refresh_token = token['refresh_token']
    session['id_token'] = new_id_token
    session['access_token'] = new_access_token
    session['refresh_token'] = new_refresh_token
    return redirect('/')

@app.route('/logout')
def logout():
    refresh_token = session.get('refresh_token')

    if refresh_token is not None:
        end_session_endpoint = f'{KEYCLOAK_ISSUER}/protocol/openid-connect/logout'

        requests.post(end_session_endpoint, data={
            "client_id": KEYCLOAK_CLIENTID,
            "client_secret": KEYCLOAK_SECRET,
            "refresh_token": refresh_token,
        })

    session.pop('id_token', None)
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    return redirect('/')
