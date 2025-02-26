


let publicKey = null;



// 页面加载时获取公钥
window.onload = async function() {
    if (typeof paillierBigint === "undefined") {
        console.log("Loading paillier-bigint...");
        await import("https://unpkg.com/paillier-bigint@3.4.3/dist/bundle.umd.js");
        console.log("paillier-bigint loaded!");
    }
    console.log(window.paillierBigint);




    await fetchPublicKey();
}

// 从后端获取公钥参数 n，并构造 Paillier 公钥对象
async function fetchPublicKey() {
    const response = await fetch('/public_key');
    const data = await response.json();
    const n = BigInt(data.n);
    // g 默认为 n + 1
    const g = n + BigInt(1);
    publicKey = new paillierBigint.PublicKey(n, g);
    console.log("Public key loaded:", publicKey);
}

// 将密码字符串转换为大整数（UTF-8编码）
function mapPasswordToInt(password) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(password);
    let hex = "";
    for (let b of bytes) {
        hex += b.toString(16).padStart(2, '0');
    }
    return BigInt("0x" + hex);
}

// 注册（设置）密码：前端加密后发送给后端
async function registerPassword() {
    if (!publicKey) {
        alert("Public key not loaded yet.");
        return;
    }
    const password = document.getElementById('password').value;
    if (!password) {
        alert("Please enter a password.");
        return;
    }
    const m = mapPasswordToInt(password);
    const ciphertext = publicKey.encrypt(m);
    const payload = { encrypted: ciphertext.toString() };

    try {
        const response = await fetch('/set_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        alert(result.message || result.error);
    } catch (err) {
        console.error(err);
        alert("Error setting password");
    }
}

// 验证密码：前端加密后发送给后端，对比存储密文
async function verifyPassword() {
    if (!publicKey) {
        alert("Public key not loaded yet.");
        return;
    }
    const password = document.getElementById('verifyPassword').value;
    if (!password) {
        alert("Please enter a password to verify.");
        return;
    }
    const m = mapPasswordToInt(password);
    const ciphertext = publicKey.encrypt(m);
    const payload = { encrypted: ciphertext.toString() };

    try {
        const response = await fetch('/verify_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        if (result.password_match) {
            alert("Password verified successfully!");
        } else {
            alert("Password verification failed.");
        }
    } catch (err) {
        console.error(err);
        alert("Error verifying password");
    }
}
