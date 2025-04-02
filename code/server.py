from flask import Flask, jsonify, request, send_from_directory
from flask_talisman import Talisman
from phe import paillier, EncryptedNumber

app = Flask(__name__, static_folder='static')

csp = {
    'default-src': ["'self'", 'https://unpkg.com'],
    'script-src': ["'self'", 'https://unpkg.com', "'unsafe-inline'"]
}
Talisman(app, content_security_policy=csp)

# Generate keys once when the server starts
public_key, private_key = paillier.generate_paillier_keypair()
users_db = {}

@app.route('/')
def index():
    return send_from_directory('static', 'client.html')

@app.route('/public_key', methods=['GET'])
def get_public_key():
    return jsonify({'n': str(public_key.n), 'g': str(public_key.g)})

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    encrypted_data = data.get('encrypted_data')

    if not username or not encrypted_data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if username in users_db:
        return jsonify({'error': 'Username already exists'}), 400
    
    # Make sure we're storing the entire encrypted_data object
    users_db[username] = encrypted_data
    print(f"User {username} registered with data: {list(encrypted_data.keys())}")
    
    return jsonify({"message": "User registered successfully"})

@app.route('/verify_password', methods=['POST'])
def verify_password():
    data = request.json
    username = data.get('username')
    encrypted_password = data.get('encrypted_password')
    
    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        # Get the stored encrypted password
        stored_encrypted_password = users_db[username]['encrypted_password']
        
        # Convert to EncryptedNumber objects for homomorphic comparison
        stored_enc_num = EncryptedNumber(public_key, int(stored_encrypted_password), 0)
        input_enc_num = EncryptedNumber(public_key, int(encrypted_password), 0)
        
        # Compute difference
        diff = stored_enc_num - input_enc_num
        difference = private_key.decrypt(diff)
        
        # Check if passwords match
        match = (difference == 0)
        
        return jsonify({"password_match": match})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user_profile')
def user_profile():
    return send_from_directory('static', 'user_profile.html')

@app.route('/get_user_profile', methods=['GET'])
def get_user_profile():
    username = request.args.get('username')

    if not username:
        return jsonify({'error': 'No username provided'}), 400

    if username not in users_db:
        return jsonify({'error': 'User not found'}), 404

    # Return the encrypted data to the client
    encrypted_data = users_db[username]
    return jsonify(encrypted_data)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=False)