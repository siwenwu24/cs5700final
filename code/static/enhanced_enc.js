// At the top of enhanced_enc.js, replace the current RSA setup with:
let publicKey = null; // Homomorphic encryption public key
let rsaEncrypt = new JSEncrypt();
let rsaDecrypt = new JSEncrypt();

// Improved key management
function generateRSAKeyPair() {
    // Generate a new key pair
    rsaEncrypt.getKey();
    
    // Get the keys as strings
    const publicKeyString = rsaEncrypt.getPublicKey();
    const privateKeyString = rsaEncrypt.getPrivateKey();
    
    // Store both keys
    localStorage.setItem('rsaPublicKey', publicKeyString);
    localStorage.setItem('rsaPrivateKey', privateKeyString);
    
    console.log("New RSA keys generated and stored");
    
    return { publicKeyString, privateKeyString };
}

// In the window.onload function, replace the key loading part:
window.onload = async function() {
    if (typeof paillierBigint === "undefined") {
        console.log("Loading paillier-bigint...");
        await import("https://unpkg.com/paillier-bigint@3.4.3/dist/bundle.umd.js");
        console.log("paillier-bigint loaded!");
    }
    
    // Load RSA keys
    const storedPublicKey = localStorage.getItem('rsaPublicKey');
    const storedPrivateKey = localStorage.getItem('rsaPrivateKey');
    
    if (!storedPublicKey || !storedPrivateKey) {
        console.log("No RSA keys found - generating new ones");
        generateRSAKeyPair();
    } else {
        console.log("Loading stored RSA keys");
        rsaEncrypt.setPublicKey(storedPublicKey);
        rsaDecrypt.setPrivateKey(storedPrivateKey);
    }
    
    await fetchPublicKey();
};

async function fetchPublicKey() {
    try {
        const response = await fetch('/public_key');
        const data = await response.json();
        const n = BigInt(data.n);
        const g = data.g ? BigInt(data.g) : n + BigInt(1);
        publicKey = new paillierBigint.PublicKey(n, g);
        console.log("Homomorphic public key loaded");
    } catch (error) {
        console.error("Error loading public key:", error);
    }
}

function mapPasswordToInt(password) {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(password);
    let hex = "";
    for (let b of bytes) {
        hex += b.toString(16).padStart(2, '0');
    }
    return BigInt("0x" + hex);
}

async function registerUser() {
    if (!publicKey) {
        alert("Public key not loaded yet. Please try again.");
        await fetchPublicKey();
        return;
    }
    
    const username = document.getElementById('username').value;
    const firstName = document.getElementById('firstName').value;
    const lastName = document.getElementById('lastName').value;
    const age = document.getElementById('age').value;
    const profession = document.getElementById('profession').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password || !firstName || !lastName || !age || !profession) {
        alert("Please fill in all fields.");
        return;
    }
    
    try {
        // Ensure we have valid RSA keys
        const storedPublicKey = localStorage.getItem('rsaPublicKey');
        if (!storedPublicKey) {
            alert("RSA keys not found. Generating new ones.");
            generateRSAKeyPair();
        }
        
        // Make sure RSA encrypter is set up with the public key
        rsaEncrypt.setPublicKey(localStorage.getItem('rsaPublicKey'));
        
        // Encrypt the password using homomorphic encryption
        const homomorphicPassword = publicKey.encrypt(mapPasswordToInt(password));
        
        // Store the plaintext username in localStorage for later use
        // (We'll need the unencrypted username for login/verification)
        localStorage.setItem('lastUsername', username);
        
        // Encrypt the username along with all other fields
        const encryptedData = {
            encrypted_username: rsaEncrypt.encrypt(username),
            encrypted_firstName: rsaEncrypt.encrypt(firstName),
            encrypted_lastName: rsaEncrypt.encrypt(lastName),
            encrypted_age: rsaEncrypt.encrypt(age.toString()),
            encrypted_profession: rsaEncrypt.encrypt(profession),
            encrypted_password: homomorphicPassword.toString()
        };
        
        // Send the data to the server
        const payload = {
            username: username,  // We still need a plaintext identifier for the server
            encrypted_data: encryptedData
        };
        
        const response = await fetch('/register_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }
        
        alert('Registration successful! You can now login.');
        // Optionally clear the form or redirect
    } catch (err) {
        console.error("Registration error:", err);
        alert("Error registering user: " + err.message);
    }
}

async function verifyPassword() {
    // At the beginning of verifyPassword function
    if (!publicKey) {
        await fetchPublicKey();
        if (!publicKey) {
            alert("Failed to load encryption keys. Please refresh and try again.");
            return;
        }
    }

    // Check for RSA private key
    const privateKey = localStorage.getItem('privateKey');
    if (!privateKey) {
        alert("Decryption keys not found. Please register again.");
        return;
    }
    
    const username = document.getElementById('verifyUsername').value;
    const password = document.getElementById('verifyPassword').value;
    
    if (!username || !password) {
        alert("Please enter username and password to verify.");
        return;
    }
    
    try {
        // Get the user data first to get the stored encrypted password
        const profileResponse = await fetch(`/get_user_profile?username=${encodeURIComponent(username)}`);
        if (!profileResponse.ok) {
            const errorData = await profileResponse.json();
            alert(errorData.error || "User not found");
            return;
        }
        
        const userData = await profileResponse.json();
        const storedEncryptedPassword = userData.encrypted_password;
        
        // Encrypt the input password for comparison
        const homomorphicPassword = publicKey.encrypt(mapPasswordToInt(password));
        
        const payload = { 
            username, 
            encrypted_password: homomorphicPassword.toString() 
        };
        
        const response = await fetch('/verify_password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        
        if (!response.ok) {
            alert(result.error || "Error verifying password");
            return;
        }
        
        if (result.password_match) {
            window.location.href = `/user_profile?username=${encodeURIComponent(username)}`;
        } else {
            alert("Password verification failed.");
        }
    } catch (err) {
        console.error(err);
        alert("Error verifying password: " + err.message);
    }
}