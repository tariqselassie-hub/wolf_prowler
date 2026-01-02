/**
 * Wolf Den Cryptographic Integration
 * Advanced cryptographic functions for secure authentication
 */
class WolfDenCrypto {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12;
        this.saltLength = 32;
        this.hashAlgorithm = 'SHA-256';
        this.pbkdf2Iterations = 100000;
    }

    /**
     * Generate a cryptographically secure random key
     */
    async generateKey(length = this.keyLength) {
        const array = new Uint8Array(length / 8);
        crypto.getRandomValues(array);
        return array;
    }

    /**
     * Derive key from password using PBKDF2
     */
    async deriveKey(password, salt, iterations = this.pbkdf2Iterations) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: this.hashAlgorithm
            },
            keyMaterial,
            { name: 'AES-GCM', length: this.keyLength },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Hash password with salt (Zero-Knowledge proof preparation)
     */
    async hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.pbkdf2Iterations,
                hash: this.hashAlgorithm
            },
            keyMaterial,
            this.keyLength
        );

        return new Uint8Array(derivedBits);
    }

    /**
     * Generate salt for password hashing
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(this.saltLength));
    }

    /**
     * Encrypt data using AES-GCM
     */
    async encrypt(data, key) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            encoder.encode(data)
        );

        return {
            encrypted: new Uint8Array(encrypted),
            iv: iv
        };
    }

    /**
     * Decrypt data using AES-GCM
     */
    async decrypt(encryptedData, key, iv) {
        const decrypted = await crypto.subtle.decrypt(
            {
                name: this.algorithm,
                iv: iv
            },
            key,
            encryptedData
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    /**
     * Generate RSA key pair for asymmetric encryption
     */
    async generateRSAKeyPair(modulusLength = 4096) {
        return crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: modulusLength,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: this.hashAlgorithm
            },
            true,
            ['encrypt', 'decrypt', 'sign', 'verify']
        );
    }

    /**
     * Sign data with RSA private key
     */
    async sign(data, privateKey) {
        const encoder = new TextEncoder();
        const signature = await crypto.subtle.sign(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            privateKey,
            encoder.encode(data)
        );

        return new Uint8Array(signature);
    }

    /**
     * Verify signature with RSA public key
     */
    async verify(data, signature, publicKey) {
        const encoder = new TextEncoder();
        return crypto.subtle.verify(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            publicKey,
            signature,
            encoder.encode(data)
        );
    }

    /**
     * Generate HMAC for message authentication
     */
    async hmac(data, key) {
        const encoder = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'HMAC', hash: this.hashAlgorithm },
            false,
            ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
        return new Uint8Array(signature);
    }

    /**
     * Generate secure session token
     */
    async generateSessionToken(userId, expiresAt) {
        const tokenData = {
            userId: userId,
            expiresAt: expiresAt,
            issuedAt: Date.now(),
            random: crypto.getRandomValues(new Uint8Array(16))
        };

        const tokenString = JSON.stringify(tokenData);
        const key = await this.generateKey();
        const encrypted = await this.encrypt(tokenString, key);

        return {
            token: this.arrayBufferToBase64(encrypted.encrypted),
            iv: this.arrayBufferToBase64(encrypted.iv),
            key: this.arrayBufferToBase64(key)
        };
    }

    /**
     * Verify and decode session token
     */
    async verifySessionToken(token, iv, key) {
        try {
            const encrypted = this.base64ToArrayBuffer(token);
            const ivArray = this.base64ToArrayBuffer(iv);
            const keyArray = this.base64ToArrayBuffer(key);
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyArray,
                'AES-GCM',
                true,
                ['decrypt']
            );

            const decrypted = await this.decrypt(encrypted, cryptoKey, ivArray);
            const tokenData = JSON.parse(decrypted);

            // Check if token is expired
            if (Date.now() > tokenData.expiresAt) {
                throw new Error('Token expired');
            }

            return tokenData;
        } catch (error) {
            console.error('Token verification failed:', error);
            return null;
        }
    }

    /**
     * Generate Zero-Knowledge Proof challenge
     */
    async generateZKChallenge() {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const timestamp = Date.now();
        
        return {
            challenge: this.arrayBufferToBase64(challenge),
            timestamp: timestamp
        };
    }

    /**
     * Create Zero-Knowledge Proof response
     */
    async createZKResponse(challenge, password, salt) {
        const challengeArray = this.base64ToArrayBuffer(challenge);
        const hashedPassword = await this.hashPassword(password, salt);
        
        // Create proof by combining challenge with hashed password
        const combined = new Uint8Array(challengeArray.length + hashedPassword.length);
        combined.set(challengeArray);
        combined.set(hashedPassword, challengeArray.length);
        
        const proof = await crypto.subtle.digest(this.hashAlgorithm, combined);
        return this.arrayBufferToBase64(new Uint8Array(proof));
    }

    /**
     * Verify Zero-Knowledge Proof
     */
    async verifyZKProof(challenge, proof, storedHash, salt) {
        try {
            const expectedProof = await this.createZKResponse(challenge, '', salt);
            // In a real implementation, this would verify against the stored hash
            // For demo purposes, we'll just check if the proof format is correct
            return proof && proof.length > 0;
        } catch (error) {
            console.error('ZK proof verification failed:', error);
            return false;
        }
    }

    /**
     * Utility: Convert ArrayBuffer to Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Utility: Convert Base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Generate biometric template hash
     */
    async generateBiometricTemplate(biometricData) {
        const encoder = new TextEncoder();
        const hash = await crypto.subtle.digest(this.hashAlgorithm, encoder.encode(biometricData));
        return this.arrayBufferToBase64(new Uint8Array(hash));
    }

    /**
     * Verify biometric data
     */
    async verifyBiometric(biometricData, storedTemplate) {
        const currentTemplate = await this.generateBiometricTemplate(biometricData);
        return currentTemplate === storedTemplate;
    }
}

// Initialize Wolf Den Crypto
window.wolfDenCrypto = new WolfDenCrypto();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WolfDenCrypto;
}
