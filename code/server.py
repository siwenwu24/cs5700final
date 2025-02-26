from flask import Flask, jsonify, request, send_from_directory
from flask_talisman import Talisman
from phe import paillier, EncryptedNumber

app = Flask(__name__, static_folder='static')

# 自定义 CSP，允许从 unpkg.com 加载脚本并执行内联脚本
# 注意：'unsafe-inline' 会降低安全性，生产环境中更推荐使用 nonce 或 sha256 校验
csp = {
    'default-src': [
        "'self'",
        'https://unpkg.com'
    ],
    'script-src': [
        "'self'",
        'https://unpkg.com',
        "'unsafe-inline'"
    ]
}
Talisman(app, content_security_policy=csp)

# 生成 Paillier 公钥和私钥对（服务器持有私钥）
public_key, private_key = paillier.generate_paillier_keypair()

# 用于演示存储密码加密结果（只存储在内存里，不可用于生产）
encrypted_stored = None

@app.route('/')
def index():
    """
    访问根路径时，返回 static/client.html 页面
    """
    return send_from_directory('static', 'client.html')

@app.route('/public_key', methods=['GET'])
def get_public_key():
    """
    返回公钥给前端，供其进行同态加密
    这里只传 n；g 默认为 n + 1
    """
    return jsonify({'n': str(public_key.n)})

@app.route('/set_password', methods=['POST'])
def set_password():
    """
    接收前端加密后的密码密文并存储
    """
    global encrypted_stored
    data = request.json
    encrypted_str = data.get('encrypted')
    if not encrypted_str:
        return jsonify({'error': 'Missing encrypted password'}), 400

    try:
        ciphertext_int = int(encrypted_str)
    except ValueError:
        return jsonify({'error': 'Invalid encrypted value'}), 400

    # 将密文恢复为 EncryptedNumber 对象
    encrypted_stored = EncryptedNumber(public_key, ciphertext_int, 0)
    return jsonify({"message": "Password set successfully"})

@app.route('/verify_password', methods=['POST'])
def verify_password_route():
    """
    接收前端加密后的密码密文，与存储的密文做同态减法验证
    """
    global encrypted_stored
    if encrypted_stored is None:
        return jsonify({'error': 'Password not set'}), 400

    data = request.json
    encrypted_str = data.get('encrypted')
    if not encrypted_str:
        return jsonify({'error': 'Missing encrypted password'}), 400

    try:
        ciphertext_int = int(encrypted_str)
    except ValueError:
        return jsonify({'error': 'Invalid encrypted value'}), 400

    input_encrypted = EncryptedNumber(public_key, ciphertext_int, 0)
    diff = encrypted_stored - input_encrypted  # 同态减法
    difference = private_key.decrypt(diff)
    match = (difference == 0)
    return jsonify({"password_match": match})

if __name__ == '__main__':
    # 使用 HTTPS 证书和私钥运行
    app.run(ssl_context=('cert.pem', 'key.pem'))

