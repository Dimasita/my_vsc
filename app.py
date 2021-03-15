from flask import Flask, request, render_template, jsonify, redirect
from authlib.integrations.flask_client import OAuth
from datetime import timedelta, datetime
import binascii
import os
import logging
import jwt
import pymysql


app = Flask(__name__)
app.secret_key = "Xz[JddQ(SveH@ezye$u^B{2t3[beT4LEYV`d`7!n'f('B%Q~]+K]06tRQy`FSyt"
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'db': 'codeserver',
}

oauth = OAuth(app)
oauth.register(
    name='github',
    client_id="c5aceb2a47c7b6d4af52",
    client_secret="72ae1040aab8209c63254cc07da40d6b360e0baa",
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email repo'}
)

logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s %(levelname)s:%(message)s')


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/login')
def login():
    return oauth.github.authorize_redirect('http://domain.com/authorize')


@app.route('/authorize')
def authorize():
    token = oauth.github.authorize_access_token()
    resp = oauth.github.get('user', token=token)
    profile = resp.json()
    git_id = profile['id']

    git_token = token['access_token']
    refresh_token = generate_token()
    refresh_token_expire = datetime.now() + timedelta(days=30)
    access_token = encode_auth_token(user_id=git_id)
    if not access_token:
        return "Server error", 500

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            query = "select id from users where git_id = %s"
            cursor.execute(query, git_id)
            row = cursor.fetchone()

            if not row:
                query = "insert into users value (default, %s, %s, %s, %s)"
                cursor.execute(query, (git_id, git_token, refresh_token, refresh_token_expire))
            else:
                uid = row[0]
                query = "update users set github_token = %s, refresh_token = %s, " \
                        "refresh_token_expire = %s where id = %s"
                cursor.execute(query, (git_token, refresh_token, refresh_token_expire, uid))

            connection.commit()

            tokens = {'access_token': access_token, 'refresh_token': refresh_token}

    except Exception as e:
        logging.exception("Exception occurred")
        return "Server error", 500
    finally:
        connection.close()

    if not tokens:
        return "Server error", 500

    print(tokens)
    return redirect('/')


@app.route('/update', methods=['PUT'])
def update_token():
    if not (request.json and 'refresh_token' in request.json):
        return "Bad Request", 400

    refresh_token = request.json['refresh_token']
    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            query = "select refresh_token_expire, git_id from users where refresh_token = %s"
            cursor.execute(query, refresh_token)
            row = cursor.fetchone()

            if not row:
                return "Unauthorized", 401
            else:
                if row[0] < datetime.now():
                    return "Unauthorized", 401
                else:
                    git_id = row[1]
                    access_token = encode_auth_token(user_id=git_id)
                    refresh_token = generate_token()
                    refresh_token_expire = datetime.now() + timedelta(days=30)

                    query = "update users set refresh_token = %s, refresh_token_expire = %s " \
                            "where git_id = %s"
                    cursor.execute(query, (refresh_token, refresh_token_expire, git_id))
                    connection.commit()

                    tokens = {'access_token': access_token, 'refresh_token': refresh_token}

    except Exception as e:
        logging.exception("Exception occurred")
        return "Server error", 500

    connection.close()

    if not tokens:
        return "Server error", 500

    print(tokens)
    return tokens, 201


@app.route('/repos', methods=['POST'])
def show_github_repos():
    if not (request.json and 'access_token' in request.json):
        return "Bad Request", 400

    access_token = request.json['access_token']
    resp = decode_auth_token(access_token)
    if resp == 0:
        return "Unauthorized", 401

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            query = "select github_token from users where git_id = %s"
            cursor.execute(query, resp)
            row = cursor.fetchone()
            if not row:
                return "Unauthorized", 401
            else:
                token = {'access_token': row[0], 'token_type': 'bearer', 'scope': 'user:email, repo'}

        connection.close()

    except Exception as e:
        logging.exception("Exception occurred")
        return "Server error", 500

    resp = oauth.github.get('user/repos', token=token).json()
    repos = []
    for repo in resp:
        repos.append(repo['name'])

    return jsonify(repos), 201


@app.route('/project', methods=['POST'])
def start_project():
    if not (request.json and 'access_token' in request.json and 'project_name' in request.json):
        return "Bad Request", 400

    access_token = request.json['access_token']
    project_name = request.json['project_name']
    resp = decode_auth_token(access_token)
    if resp == 0:
        return "Unauthorized", 401

    import subprocess
    path = 'bash/'

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:

            query = "select github_token, id from users where git_id = %s"
            cursor.execute(query, resp)
            row = cursor.fetchone()
            if not row:
                return "Unauthorized", 401

            uid = row[1]
            token = {'access_token': row[0], 'token_type': 'bearer', 'scope': 'user:email, repo'}

            profile = oauth.github.get('user', token=token).json()
            user_name = profile['name']

            profile = oauth.github.get('user/emails', token=token).json()
            email = ''
            for mail in profile:
                if mail['primary']:
                    email = mail['email']
                    break
            if email == '':
                return "Bad Request", 400

            resp = oauth.github.get('user/repos', token=token).json()
            link = ''
            for repo in resp:
                if repo['name'] == project_name:
                    link = repo['html_url']
                    break
            if link == '':
                return "Bad Request", 400

            query = "select id from projects where uid = %s and name = %s"
            cursor.execute(query, (uid, project_name))
            row = cursor.fetchone()
            if not row:
                query = "SELECT MAX(port) FROM projects"
                cursor.execute(query)
                row = cursor.fetchone()
                if not row or not row[0]:
                    port = 10000
                else:
                    port = row[0] + 1
                query = 'INSERT INTO projects VALUE (default, %s, %s, %s)'
                cursor.execute(query, (uid, project_name, port))
                container_id = connection.insert_id()
                connection.commit()

                try:
                    subprocess.check_output(
                        [path + 'create_container', str(uid), user_name,
                         project_name, 'project' + str(container_id), str(port), link, email])
                except subprocess.CalledProcessError:
                    logging.exception("Exception occurred")
                    return 'Container error', 500

            else:
                container_id = row[0]
                try:
                    subprocess.check_output([path + 'start_container', 'project' + str(container_id)])
                except subprocess.CalledProcessError:
                    logging.exception("Exception occurred")
                    return 'Container error', 500

        connection.close()

    except Exception as e:
        logging.exception("Exception occurred")
        return "Server error", 500

    access_token = encode_auth_token(project_id=container_id)
    if not access_token:
        return "Server error", 500

    return access_token, 201


def encode_auth_token(user_id=None, project_id=None):
    try:
        if not project_id:
            payload = {
                'exp': datetime.utcnow() + timedelta(minutes=30),
                'iat': datetime.utcnow(),
                'sub': user_id
            }
        else:
            payload = {
                'exp': datetime.utcnow() + timedelta(minutes=5),
                'iat': datetime.utcnow(),
                'sub': project_id
            }
        return jwt.encode(
            payload,
            app.secret_key,
            algorithm='HS256'
        )
    except Exception as e:
        logging.exception("Exception occurred")
        return e


def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.secret_key, algorithms="HS256")
        return payload['sub']
    except:
        return 0


def generate_token():
    return binascii.hexlify(os.urandom(20)).decode()


if __name__ == '__main__':
    app.run()
