from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
import jwt
import datetime
import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from flask_caching import Cache

app = Flask(__name__)
app.secret_key = 'key'

# Configure Flask-Caching
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 300})

users = {
    'user': 'password',
    'user1': 'password1'
}
algorithm = "HS256"
logging.basicConfig(level=logging.DEBUG)
active_tokens = {}

# Load RSA private key from file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load RSA public key from file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Create and verify access tokens
def create_access_token(username):
    expiration = datetime.datetime.now()+datetime.timedelta(seconds=100)  
    payload = {
        'username': username,
        'exp': expiration
    }
    token = jwt.encode(payload, app.secret_key, algorithm)
    
    # Encrypt the token using the RSA public key
    encrypted_token = public_key.encrypt(
        token.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hashed_token = hashlib.sha256(encrypted_token).hexdigest()
    
    logging.debug(f"Generated token for {username}: {token}")
    logging.debug(f"Encrypted token: {encrypted_token}")
    logging.debug(f"Hashed token: {hashed_token}")
    
    active_tokens[username] = hashed_token
    logging.debug(f"Active tokens: {active_tokens}")
    return encrypted_token

def verify_token(encrypted_token):
    try:
        # Decrypt the token using the RSA private key
        decrypted_token = private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        hashed_token = hashlib.sha256(encrypted_token).hexdigest()
        
        username = next((user for user, h_token in active_tokens.items() if h_token == hashed_token), None)
        
        if not username:
            logging.debug("Token not found in active tokens.")
            return None

        payload = jwt.decode(decrypted_token, app.secret_key, algorithms=[algorithm])
        logging.debug(f"Token verified successfully: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logging.debug("Token has expired.")
        return None
    except jwt.InvalidTokenError:
        logging.debug("Invalid token.")
        return None
    except Exception as e:
        logging.debug(f"Token verification failed: {str(e)}")
        return None

# Route for saving form data via AJAX
@app.route('/save_form_data', methods=['POST'])
def save_form_data():
    form_data = request.json  # Expecting form data as JSON
    username = request.cookies.get('username')  # Assuming username is stored in cookies
    
    if username:
        cache.set(f'form-data-{username}', form_data)
        logging.debug(f"Form data for {username} saved to cache: {form_data}")
        return jsonify({"message": "Data saved successfully"}), 200
    else:
        return jsonify({"error": "User not logged in"}), 400

# Route for the login page
@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in active_tokens:
            flash("You are already logged in. Please logout from all other devices.")
            return render_template('login.html', username=username)
        if username in users and users[username] == password:
            token = create_access_token(username)
            response = redirect(url_for('dashboard', token=token.hex()))  # Convert bytes to hex string for URL
            response.set_cookie('username', username)  # Set the username in a cookie
            return response
        else:
            flash("Invalid credentials")
            return render_template('login.html', username=username)
    return render_template('login.html')

# Route for the dashboard page
@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():
    token_hex = request.args.get('token')
    if not token_hex:
        return redirect(url_for('login'))

    try:
        token_bytes = bytes.fromhex(token_hex)  # Convert hex string back to bytes
    except ValueError:
        return redirect(url_for('login'))

    payload = verify_token(token_bytes)
    if not payload:
        return redirect(url_for('logout'))

    username = payload['username']
    unsaved_data = cache.get(f'form-data-{username}') or {}

    if request.method == 'POST':
        if 'submit' in request.form:
            unsaved_data = {
                'name': request.form.get('name'),
                'email': request.form.get('email'),
                'phone': request.form.get('phone'),
                'textField': request.form.get('textField')
            }
            cache.set(f'form-data-{username}', unsaved_data)
            logging.debug(f"Form data for {username} saved to cache.")
            return redirect(url_for('dashboard', token=token_hex))

    expiration = payload['exp'] * 1000

    return render_template('dashboard.html', username=username, token=token_hex, payload=payload, expiration=expiration, unsaved_data=unsaved_data)

# Route for logout
@app.route('/logout', methods=['GET','POST'])
def logout():
    username = request.form.get('username')
    if username in active_tokens:
        del active_tokens[username]

    response = redirect(url_for('login'))

    flash("You have been logged out.")
    return response

# Route for logout from all devices
@app.route('/logout_all', methods=['GET','POST'])
def logout_all():
    username = request.form.get('username')
    if username in active_tokens:
        del active_tokens[username]

    response = redirect(url_for('login'))
 
    flash("You have been logged out from all devices.")
    return response

if __name__ == '__main__':
    app.run(debug=True)
