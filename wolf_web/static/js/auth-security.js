/**
 * Wolf Prowler Authentication Security System
 * Integrates Wolf Sec and Wolf Den for secure authentication
 */

/**
 * Custom error for API-related failures.
 */
class AuthApiError extends Error {
    constructor(message) {
        super(message);
        this.name = 'AuthApiError';
    }
}

/**
 * Manages user sessions, including creation, storage, and verification.
 */
class SessionManager {
    constructor(options) {
        this.timeout = options.timeout || 30 * 60 * 1000; // 30 minutes
        this.crypto = options.crypto;
        this.sessionKey = 'wolf_prowler_session';
        this.cookieName = 'wolf_session';
    }

    async create(username) {
        const expiresAt = Date.now() + this.timeout;
        const sessionToken = await this.crypto.generateSessionToken(username, expiresAt);

        const session = {
            username: username,
            token: sessionToken.token,
            iv: sessionToken.iv,
            key: sessionToken.key,
            expiresAt: expiresAt,
            createdAt: Date.now(),
            lastActivity: Date.now()
        };

        this.store(session);
        return session;
    }

    store(session) {
        // Use sessionStorage for security (cleared on browser close)
        sessionStorage.setItem(this.sessionKey, JSON.stringify(session));

        // Set secure cookie for additional persistence
        document.cookie = `${this.cookieName}=${session.token}; Secure; HttpOnly; SameSite=Strict; max-age=${this.timeout / 1000}`;
    }

    get() {
        try {
            const sessionData = sessionStorage.getItem(this.sessionKey);
            if (sessionData) {
                return JSON.parse(sessionData);
            }
        } catch (error) {
            console.error('Failed to parse session:', error);
        }
        return null;
    }

    clear() {
        sessionStorage.removeItem(this.sessionKey);
        document.cookie = `${this.cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    }

    async verify(session) {
        if (!session) return false;
        try {
            const tokenData = await this.crypto.verifySessionToken(
                session.token,
                session.iv,
                session.key
            );
            return tokenData && Date.now() < session.expiresAt;
        } catch (error) {
            console.error('Session verification failed:', error);
            return false;
        }
    }
}

class AuthSecuritySystem {
    constructor() {
        this.maxLoginAttempts = 3;
        this.lockoutDuration = 15 * 60 * 1000; // 15 minutes
        this.twoFactorEnabled = true;
        this.biometricEnabled = true;
        
        this.sessionManager = new SessionManager({ timeout: 30 * 60 * 1000, crypto: window.wolfDenCrypto });
        this.loginAttempts = this.getLoginAttempts();
        this.lockoutTime = this.getLockoutTime();
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkSessionValidity();
        this.updateSecurityStatus();
    }

    setupEventListeners() {
        const form = document.getElementById('loginForm');
        const togglePassword = document.getElementById('togglePassword');
        const useBiometric = document.getElementById('useBiometric');
        const cancelBiometric = document.getElementById('cancelBiometric');

        if (form) {
            form.addEventListener('submit', (e) => this.handleLogin(e));
        }

        if (togglePassword) {
            togglePassword.addEventListener('click', () => this.togglePasswordVisibility());
        }

        if (useBiometric) {
            useBiometric.addEventListener('change', (e) => this.toggleBiometricMode(e.target.checked));
        }

        if (cancelBiometric) {
            cancelBiometric.addEventListener('click', () => this.cancelBiometricAuth());
        }

        // Add keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'Enter') {
                this.handleLogin(e);
            }
        });
    }

    async handleLogin(event) {
        event.preventDefault();
        
        const username = document.getElementById('username').value;
        const twoFactorCode = document.getElementById('twoFactorCode').value;

        if (this.isAccountLocked()) {
            this.showError('Account is temporarily locked. Please try again later.');
            return;
        }

        this.setLoadingState(true);
        try {
            await this._validatePasswordProof(username);

            // If 2FA is enabled but no code is provided, show the input and wait for the next submission.
            if (this.twoFactorEnabled && !twoFactorCode) {
                this.showTwoFactorInput();
                this.setLoadingState(false); // Allow user to enter code
                return;
            }
            await this._validateTwoFactor(twoFactorCode);

            await this._validateBiometrics();

            const session = await this.sessionManager.create(username);
            this.loginSuccess(session);

        } catch (error) {
            if (error instanceof AuthApiError) {
                this.showError(error.message);
                this.incrementLoginAttempts();
                this.handleLoginError(error);
            } else {
                // Handle unexpected errors separately
                this.handleLoginError(error);
            }
        } finally {
            this.setLoadingState(false);
        }
    }

    async _validatePasswordProof(username) {
        const password = document.getElementById('password').value;
        const zkProof = await this.performZKPasswordProof(username, password);
        if (!zkProof.success) {
            throw new AuthApiError(zkProof.error || 'Invalid username or password.');
        }
    }

    async _validateTwoFactor(twoFactorCode) {
        if (this.twoFactorEnabled && twoFactorCode) {
            const isValid = await this.verifyTwoFactor(twoFactorCode);
            if (!isValid) throw new AuthApiError('Invalid two-factor code.');
        }
    }

    async _validateBiometrics() {
        if (this.biometricEnabled && document.getElementById('useBiometric').checked) {
            const isValid = await this.performBiometricAuth();
            if (!isValid) throw new AuthApiError('Biometric authentication failed.');
        }
    }

    async performZKPasswordProof(username, password) {
        try {
            // Generate challenge from server
            const challenge = await this.getAuthenticationChallenge(username);
            
            // Create Zero-Knowledge proof
            const salt = window.wolfDenCrypto.generateSalt();
            const proof = await window.wolfDenCrypto.createZKResponse(challenge.challenge, password, salt);
            
            // Send proof to server for verification
            const response = await this.verifyAuthenticationChallenge(username, proof, challenge.timestamp);
            
            return response;
        } catch (error) {
            console.error('ZK Password proof failed:', error);
            return { success: false, error: error.message };
        }
    }

    async getAuthenticationChallenge(_username) {
        // Simulate server challenge
        await new Promise(resolve => setTimeout(resolve, 250)); // Simulate network latency

        // Simulate a chance of server/network error
        if (Math.random() < 0.1) { // 10% chance of failure
            throw new AuthApiError('Failed to connect to authentication server. Please try again.');
        }

        return await window.wolfDenCrypto.generateZKChallenge();
    }

    async verifyAuthenticationChallenge(username, _proof, _timestamp) {
        // Simulate server verification
        // In production, this would be an actual API call
        await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate verification latency

        // Simulate various failure scenarios
        if (Math.random() < 0.1) { // 10% chance of server error
            throw new AuthApiError('Authentication service unavailable. Please try again later.');
        }

        // For demo purposes, let's treat a specific username as invalid
        if (username.toLowerCase() === 'baduser') {
            return { success: false, error: 'Invalid username or password.' };
        }

        // Simulate successful verification
        return { success: true, requiresTwoFactor: true, requiresBiometric: false };
    }

    async verifyTwoFactor(code) {
        // Simulate 2FA verification
        // In production, this would verify against user's 2FA app
        await new Promise(resolve => setTimeout(resolve, 500));

        // Simulate an invalid code for demo purposes
        if (code === '000000') return false;

        return /^\d{6}$/.test(code);
    }

    async performBiometricAuth() {
        return new Promise((resolve) => {
            // Show biometric scanner
            document.getElementById('biometricScanner').classList.remove('hidden');
            
            // Simulate biometric scan
            setTimeout(async () => {
                try {
                    // Check if WebAuthn is available
                    if (navigator.credentials && navigator.credentials.get) {
                        const credential = await navigator.credentials.get({
                            publicKey: {
                                challenge: window.wolfDenCrypto.generateSalt(),
                                allowCredentials: [{
                                    type: 'public-key',
                                    id: new Uint8Array(32), // User's credential ID
                                    transports: ['internal', 'usb', 'nfc', 'ble']
                                }],
                                userVerification: 'required'
                            }
                        });
                        
                        // Verify biometric data
                        const biometricData = JSON.stringify(credential);
                        const template = await window.wolfDenCrypto.generateBiometricTemplate(biometricData);
                        
                        // Store or verify template
                        const isValid = await this.verifyBiometricTemplate(template);
                        
                        document.getElementById('biometricScanner').classList.add('hidden');
                        resolve(isValid);
                    } else {
                        // Fallback for browsers without WebAuthn
                        document.getElementById('biometricScanner').classList.add('hidden');
                        resolve(true); // Auto-accept for demo
                    }
                } catch (error) {
                    document.getElementById('biometricScanner').classList.add('hidden');
                    console.error('Biometric authentication failed:', error);
                    resolve(false);
                }
            }, 3000);
        });
    }

    async verifyBiometricTemplate(template) {
        // In production, verify against stored template
        // For demo, always return true
        return true;
    }

    async checkSessionValidity() {
        const currentSession = this.sessionManager.get();
        if (currentSession) {
            const isValid = await this.sessionManager.verify(currentSession);
            if (isValid) {
                // Redirect to dashboard if session is valid
                window.location.href = '/static/dashboard_modern.html';
            } else {
                this.sessionManager.clear();
            }
        }
    }

    loginSuccess(session) {
        // Clear login attempts
        this.clearLoginAttempts();
        
        // Show success message
        this.showSuccess('Authentication successful! Redirecting...');
        
        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = '/static/dashboard_modern.html';
        }, 1500);
    }

    handleLoginError(error) {
        // Log unexpected errors for debugging
        if (!(error instanceof AuthApiError)) {
            console.error('An unexpected error occurred during login:', error);
            this.showError('An unexpected error occurred. Please check the console.');
        }

        // Check if account should be locked
        if (this.loginAttempts >= this.maxLoginAttempts) {
            this.lockAccount();
        }
    }

    incrementLoginAttempts() {
        this.loginAttempts++;
        localStorage.setItem('wolf_login_attempts', this.loginAttempts.toString());
        localStorage.setItem('wolf_login_timestamp', Date.now().toString());
    }

    getLoginAttempts() {
        const attempts = localStorage.getItem('wolf_login_attempts');
        return attempts ? parseInt(attempts) : 0;
    }

    clearLoginAttempts() {
        localStorage.removeItem('wolf_login_attempts');
        localStorage.removeItem('wolf_login_timestamp');
        localStorage.removeItem('wolf_lockout_time');
    }

    lockAccount() {
        this.lockoutTime = Date.now() + this.lockoutDuration;
        localStorage.setItem('wolf_lockout_time', this.lockoutTime.toString());
        
        this.showError('Account locked due to too many failed attempts. Please try again in 15 minutes.');
        this.disableLoginForm();
    }

    isAccountLocked() {
        if (this.lockoutTime && Date.now() < this.lockoutTime) {
            return true;
        }
        
        // Reset lockout if time has passed
        if (this.lockoutTime && Date.now() >= this.lockoutTime) {
            this.clearLoginAttempts();
            this.lockoutTime = null;
        }
        
        return false;
    }

    getLockoutTime() {
        const lockout = localStorage.getItem('wolf_lockout_time');
        return lockout ? parseInt(lockout) : null;
    }

    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = document.querySelector('#togglePassword i');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.setAttribute('data-lucide', 'eye-off');
        } else {
            passwordInput.type = 'password';
            toggleIcon.setAttribute('data-lucide', 'eye');
        }
        
        lucide.createIcons();
    }

    showTwoFactorInput() {
        document.getElementById('twoFactorSection').classList.remove('hidden');
        document.getElementById('twoFactorCode').focus();
    }

    toggleBiometricMode(enabled) {
        if (enabled) {
            // Check if biometrics are available
            if (!navigator.credentials) {
                this.showError('Biometric authentication is not supported on this device.');
                document.getElementById('useBiometric').checked = false;
                return;
            }
        }
    }

    cancelBiometricAuth() {
        document.getElementById('biometricScanner').classList.add('hidden');
        document.getElementById('useBiometric').checked = false;
    }

    setLoadingState(loading) {
        const loginBtn = document.getElementById('loginBtn');
        const spinner = loading ? '<i data-lucide="loader-2" class="w-5 h-5 animate-spin"></i>' : '<i data-lucide="shield-check" class="w-5 h-5"></i>';
        
        loginBtn.innerHTML = `
            ${spinner}
            <span>${loading ? 'Authenticating...' : 'Secure Login'}</span>
        `;
        loginBtn.disabled = loading;
        
        if (loading) {
            lucide.createIcons();
        }
    }

    disableLoginForm() {
        document.getElementById('loginForm').querySelectorAll('input, button').forEach(el => {
            el.disabled = true;
        });
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showNotification(message, type = 'info') {
        if (window.showNotification) {
            window.showNotification('Authentication', message, type);
        } else {
            console.log(`[${type.toUpperCase()}] ${message}`);
        }
    }

    updateSecurityStatus() {
        // Update security indicators
        const statusElements = document.querySelectorAll('.crypto-indicator, .security-badge');
        statusElements.forEach(el => {
            el.style.opacity = '1';
        });
    }
}

// Initialize authentication system
window.authSecuritySystem = null;

/**
 * Creates an instance of the AuthSecuritySystem and attaches it to the window.
 * This function is executed once the DOM is fully loaded.
 */
async function initializeAuthSystem() {
    const authSystem = new AuthSecuritySystem();
    window.authSecuritySystem = authSystem;
    
    // Make available globally
    window.AuthSecuritySystem = AuthSecuritySystem;

    // Expose a test runner to the console for development/testing
    window.runAuthTests = () => authSystem.runTests();
    console.info("AuthSecuritySystem initialized. Run 'runAuthTests()' in the console to execute unit tests.");
}

// Wait for the DOM to be fully loaded before initializing
document.addEventListener('DOMContentLoaded', initializeAuthSystem);

// --- UNIT TESTING SUITE ---

/**
 * Simple assertion utilities for tests.
 */
const assert = {
    async rejects(promise, errorType, testName) {
        try {
            await promise;
            console.error(`❌ FAIL: ${testName}. Expected promise to reject with ${errorType.name}, but it resolved.`);
        } catch (error) {
            if (error instanceof errorType) {
                console.log(`✅ PASS: ${testName}`);
            } else {
                console.error(`❌ FAIL: ${testName}. Expected rejection with ${errorType.name}, but got ${error.constructor.name}.`);
            }
        }
    },
    async doesNotReject(promise, testName) {
        try {
            await promise;
            console.log(`✅ PASS: ${testName}`);
        } catch (error) {
            console.error(`❌ FAIL: ${testName}. Expected promise to resolve, but it rejected with:`, error);
        }
    }
};

/**
 * Adds a test runner to the AuthSecuritySystem class.
 * This is a non-production method for development and verification.
 */
AuthSecuritySystem.prototype.runTests = async function() {
    console.group("AuthSecuritySystem Unit Tests");

    // Mock dependencies
    const original_performZKPasswordProof = this.performZKPasswordProof;
    const original_verifyTwoFactor = this.verifyTwoFactor;
    const original_performBiometricAuth = this.performBiometricAuth;
    const original_getElementById = document.getElementById;

    // --- Test Suite for _validatePasswordProof ---
    console.group("Testing: _validatePasswordProof");
    document.getElementById = () => ({ value: 'test_password' }); // Mock password field

    this.performZKPasswordProof = async () => ({ success: true });
    await assert.doesNotReject(
        this._validatePasswordProof('testuser'),
        '_validatePasswordProof should pass with a valid proof'
    );

    this.performZKPasswordProof = async () => ({ success: false, error: 'Invalid proof' });
    await assert.rejects(
        this._validatePasswordProof('testuser'),
        AuthApiError,
        '_validatePasswordProof should fail with an invalid proof'
    );
    console.groupEnd();

    // --- Test Suite for _validateTwoFactor ---
    console.group("Testing: _validateTwoFactor");
    this.twoFactorEnabled = true;
    this.verifyTwoFactor = async (code) => code === '123456';

    await assert.doesNotReject(
        this._validateTwoFactor('123456'),
        '_validateTwoFactor should pass with a valid code'
    );

    await assert.rejects(
        this._validateTwoFactor('654321'),
        AuthApiError,
        '_validateTwoFactor should fail with an invalid code'
    );

    this.twoFactorEnabled = false;
    await assert.doesNotReject(
        this._validateTwoFactor(''),
        '_validateTwoFactor should pass if 2FA is not enabled'
    );
    console.groupEnd();

    // --- Test Suite for _validateBiometrics ---
    console.group("Testing: _validateBiometrics");
    this.biometricEnabled = true;
    document.getElementById = () => ({ checked: true }); // Mock biometric checkbox
    this.performBiometricAuth = async () => true;
    await assert.doesNotReject(this._validateBiometrics(), '_validateBiometrics should pass with valid biometrics');

    this.performBiometricAuth = async () => false;
    await assert.rejects(this._validateBiometrics(), AuthApiError, '_validateBiometrics should fail with invalid biometrics');

    document.getElementById = () => ({ checked: false }); // Mock unchecked box
    await assert.doesNotReject(this._validateBiometrics(), '_validateBiometrics should pass if biometric is not selected');
    console.groupEnd();

    // Restore original methods
    this.performZKPasswordProof = original_performZKPasswordProof;
    this.verifyTwoFactor = original_verifyTwoFactor;
    this.performBiometricAuth = original_performBiometricAuth;
    document.getElementById = original_getElementById;

    console.groupEnd();
};

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthSecuritySystem;
}
