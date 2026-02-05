/**
 * Secure Authentication Handler
 * CSRF protection, secure storage, session management
 */

class SecureAuth {
  constructor() {
    this.csrfToken = null;
    this.sessionCheckInterval = null;
    this.init();
  }

  async init() {
    await this.fetchCSRFToken();
    this.setupEventListeners();
    this.checkExistingSession();
  }

  async fetchCSRFToken() {
    try {
      const response = await fetch('/api/csrf-token', {
        credentials: 'include'
      });
      const data = await response.json();
      this.csrfToken = data.csrfToken;
      
      // Set in hidden field
      const tokenField = document.getElementById('csrfToken');
      if (tokenField) tokenField.value = this.csrfToken;
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
      this.showError('Security initialization failed. Please refresh.');
    }
  }

  setupEventListeners() {
    const loginForm = document.getElementById('loginForm');
    const togglePassword = document.querySelector('.toggle-password');

    if (loginForm) {
      loginForm.addEventListener('submit', (e) => this.handleLogin(e));
    }

    if (togglePassword) {
      togglePassword.addEventListener('click', () => this.togglePassword());
    }

    // Auto-logout on tab close (optional security enhancement)
    window.addEventListener('beforeunload', () => {
      // Optional: Clear sensitive form data
      const passwordField = document.getElementById('password');
      if (passwordField) passwordField.value = '';
    });
  }

  async handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');

    // Client-side validation
    if (!this.validateInput(username, password)) {
      return;
    }

    // UI loading state
    btn.disabled = true;
    btnText.textContent = 'Authenticating...';
    btnLoader.classList.remove('hidden');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CSRF-Token': this.csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (response.ok) {
        this.handleLoginSuccess(data);
      } else {
        this.handleLoginError(data);
      }

    } catch (error) {
      this.showError('Network error. Please check your connection.');
    } finally {
      btn.disabled = false;
      btnText.textContent = 'Secure Login';
      btnLoader.classList.add('hidden');
      // Clear password
      document.getElementById('password').value = '';
    }
  }

  validateInput(username, password) {
    const usernameRegex = /^[a-zA-Z0-9._-]{3,50}$/;
    
    if (!usernameRegex.test(username)) {
      this.showError('Invalid username format');
      return false;
    }
    
    if (password.length < 8) {
      this.showError('Password must be at least 8 characters');
      return false;
    }
    
    return true;
  }

  handleLoginSuccess(data) {
    // Clear any stored data
    sessionStorage.clear();
    
    // Store minimal session info (not sensitive data)
    sessionStorage.setItem('mo_session', JSON.stringify({
      username: data.username,
      role: data.role,
      loginTime: Date.now()
    }));

    // Redirect to capture page
    window.location.href = '/pages/capture.html';
  }

  handleLoginError(data) {
    // Generic error for security
    this.showError(data.error || 'Authentication failed. Please try again.');
    
    // Clear sensitive fields
    document.getElementById('password').value = '';
    
    // Refresh CSRF token after failed attempt
    this.fetchCSRFToken();
  }

  showError(message) {
    const errorBanner = document.getElementById('errorMessage');
    if (errorBanner) {
      errorBanner.textContent = message;
      errorBanner.classList.remove('hidden');
      
      setTimeout(() => {
        errorBanner.classList.add('hidden');
      }, 5000);
    }
  }

  togglePassword() {
    const passwordField = document.getElementById('password');
    const toggleBtn = document.querySelector('.toggle-password');
    
    if (passwordField.type === 'password') {
      passwordField.type = 'text';
      toggleBtn.textContent = '🙈';
    } else {
      passwordField.type = 'password';
      toggleBtn.textContent = '👁️';
    }
  }

  async checkExistingSession() {
    try {
      const response = await fetch('/api/auth/status', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.authenticated) {
          window.location.href = '/pages/capture.html';
        }
      }
    } catch (error) {
      // Silent fail - user needs to login
    }
  }

  // Session management
  startSessionCheck() {
    this.sessionCheckInterval = setInterval(async () => {
      try {
        const response = await fetch('/api/auth/status', {
          credentials: 'include'
        });
        
        if (!response.ok) {
          this.handleSessionExpiry();
        }
      } catch (error) {
        this.handleSessionExpiry();
      }
    }, 5 * 60 * 1000); // Check every 5 minutes
  }

  handleSessionExpiry() {
    clearInterval(this.sessionCheckInterval);
    alert('Your session has expired. Please login again.');
    window.location.href = '/pages/login.html';
  }

  async logout() {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'CSRF-Token': this.csrfToken
        },
        credentials: 'include'
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      sessionStorage.clear();
      window.location.href = '/pages/login.html';
    }
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  new SecureAuth();
});
