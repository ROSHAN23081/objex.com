/**
 * Secure Data Capture Handler
 * Real-time validation, encryption indicators, session management
 */

class SecureCapture {
  constructor() {
    this.csrfToken = null;
    this.sessionData = [];
    this.countdownInterval = null;
    this.sessionExpiry = Date.now() + (30 * 60 * 1000); // 30 minutes
    this.init();
  }

  async init() {
    await this.checkAuth();
    await this.fetchCSRFToken();
    this.setupEventListeners();
    this.startCountdown();
    this.loadSessionData();
    this.updateSessionDisplay();
  }

  async checkAuth() {
    try {
      const response = await fetch('/api/auth/status', {
        credentials: 'include'
      });
      
      if (!response.ok) {
        window.location.href = '/pages/login.html';
        return;
      }
      
      const data = await response.json();
      document.getElementById('currentUser').textContent = data.username;
      
    } catch (error) {
      window.location.href = '/pages/login.html';
    }
  }

  async fetchCSRFToken() {
    try {
      const response = await fetch('/api/csrf-token', {
        credentials: 'include'
      });
      const data = await response.json();
      this.csrfToken = data.csrfToken;
      
      const tokenField = document.getElementById('csrfToken');
      if (tokenField) tokenField.value = this.csrfToken;
    } catch (error) {
      this.showError('Security token refresh failed');
    }
  }

  setupEventListeners() {
    const form = document.getElementById('captureForm');
    const logoutBtn = document.getElementById('logoutBtn');
    
    // Real-time validation
    const phoneInput = document.getElementById('phoneNumber');
    const phoneConfirm = document.getElementById('confirmPhoneNumber');
    const codeInput = document.getElementById('safetyCode');
    const codeConfirm = document.getElementById('confirmSafetyCode');

    const checkMatch = (input1, input2, indicatorId) => {
      const indicator = document.getElementById(indicatorId);
      if (input2.value) {
        if (input1.value === input2.value) {
          indicator.textContent = '✓ Match';
          indicator.className = 'match-indicator match-success';
          input2.classList.remove('mismatch');
        } else {
          indicator.textContent = '✗ Mismatch';
          indicator.className = 'match-indicator match-error';
          input2.classList.add('mismatch');
        }
      } else {
        indicator.textContent = '';
      }
    };

    phoneConfirm.addEventListener('input', () => checkMatch(phoneInput, phoneConfirm, 'phoneMatch'));
    codeConfirm.addEventListener('input', () => checkMatch(codeInput, codeConfirm, 'codeMatch'));

    // Auto-uppercase safety codes
    [codeInput, codeConfirm].forEach(input => {
      input.addEventListener('input', (e) => {
        e.target.value = e.target.value.toUpperCase();
      });
    });

    if (form) {
      form.addEventListener('submit', (e) => this.handleCapture(e));
    }

    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => this.logout());
    }

    // Warn before unload if unsaved data
    window.addEventListener('beforeunload', (e) => {
      if (this.sessionData.length > 0 && !window.sessionExpired) {
        e.preventDefault();
        e.returnValue = 'You have captured data that will be lost.';
      }
    });
  }

  async handleCapture(e) {
    e.preventDefault();
    
    const phoneNumber = document.getElementById('phoneNumber').value.trim();
    const confirmPhone = document.getElementById('confirmPhoneNumber').value.trim();
    const safetyCode = document.getElementById('safetyCode').value.trim().toUpperCase();
    const confirmCode = document.getElementById('confirmSafetyCode').value.trim().toUpperCase();

    // Client-side double-entry verification
    if (phoneNumber !== confirmPhone) {
      this.showError('Phone numbers do not match');
      document.getElementById('confirmPhoneNumber').focus();
      return;
    }

    if (safetyCode !== confirmCode) {
      this.showError('Safety codes do not match');
      document.getElementById('confirmSafetyCode').focus();
      return;
    }

    // Validate E.164 phone format
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(phoneNumber)) {
      this.showError('Invalid phone number format. Use E.164 format (+1234567890)');
      return;
    }

    // Validate safety code format
    const codeRegex = /^[A-Z0-9-]{6,20}$/;
    if (!codeRegex.test(safetyCode)) {
      this.showError('Safety code must be 6-20 alphanumeric characters');
      return;
    }

    const btn = document.getElementById('captureBtn');
    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Encrypting...';

    try {
      const response = await fetch('/api/capture', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CSRF-Token': this.csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({
          phoneNumber,
          confirmPhoneNumber: confirmPhone,
          safetyCode,
          confirmSafetyCode: confirmCode
        })
      });

      const data = await response.json();

      if (response.ok) {
        this.handleCaptureSuccess(phoneNumber, safetyCode);
      } else {
        this.showError(data.error || 'Capture failed');
      }

    } catch (error) {
      this.showError('Network error. Please retry.');
    } finally {
      btn.disabled = false;
      btn.querySelector('.btn-text').textContent = '🔐 Secure Capture';
    }
  }

  handleCaptureSuccess(phone, code) {
    // Add to local preview
    this.sessionData.push({
      phone: phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2'), // Masked for display
      code: code,
      timestamp: new Date().toLocaleTimeString()
    });

    // Show success
    const successBanner = document.getElementById('captureSuccess');
    successBanner.classList.remove('hidden');
    
    setTimeout(() => {
      successBanner.classList.add('hidden');
    }, 3000);

    // Clear form
    document.getElementById('captureForm').reset();
    document.querySelectorAll('.match-indicator').forEach(el => el.textContent = '');

    // Update preview
    this.updatePreview();
    this.updateStats();

    // Refresh CSRF token after successful action
    this.fetchCSRFToken();
  }

  updatePreview() {
    const container = document.getElementById('dataPreview');
    
    if (this.sessionData.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">📭</span>
          <p>No data captured in this session yet</p>
          <span>All captures are encrypted and session-bound</span>
        </div>
      `;
      return;
    }

    container.innerHTML = this.sessionData.map(item => `
      <div class="preview-item">
        <div class="preview-info">
          <span class="preview-phone">${item.phone}</span>
          <span class="preview-time">${item.timestamp}</span>
        </div>
        <span class="preview-code">${item.code}</span>
      </div>
    `).join('');
  }

  updateStats() {
    document.getElementById('captureCount').textContent = this.sessionData.length;
  }

  updateSessionDisplay() {
    const sessionId = 'MO-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    document.getElementById('sessionId').textContent = sessionId;
    document.getElementById('footerSessionId').textContent = sessionId;
  }

  startCountdown() {
    this.countdownInterval = setInterval(() => {
      const remaining = this.sessionExpiry - Date.now();
      
      if (remaining <= 0) {
        clearInterval(this.countdownInterval);
        window.sessionExpired = true;
        alert('Session expired. All data has been securely purged.');
        this.logout();
        return;
      }

      const minutes = Math.floor(remaining / 60000);
      const seconds = Math.floor((remaining % 60000) / 1000);
      const formatted = `${minutes}:${seconds.toString().padStart(2, '0')}`;
      
      document.getElementById('countdown').textContent = formatted;
      document.getElementById('sessionTimer').textContent = formatted;

      // Warning at 5 minutes
      if (minutes === 5 && seconds === 0) {
        this.showWarning('Session expires in 5 minutes. Complete your tasks soon.');
      }

    }, 1000);
  }

  async loadSessionData() {
    try {
      const response = await fetch('/api/capture/current', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.captures && data.captures.length > 0) {
          this.sessionData = data.captures.map(c => ({
            phone: c.phoneNumber.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2'),
            code: c.safetyCode,
            timestamp: new Date(c.createdAt).toLocaleTimeString()
          }));
          this.updatePreview();
          this.updateStats();
        }
      }
    } catch (error) {
      console.error('Failed to load session data');
    }
  }

  showError(message) {
    // Create error toast
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.innerHTML = `
      <span class="error-icon">⚠️</span>
      <span>${message}</span>
    `;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.remove(), 5000);
  }

  showWarning(message) {
    const toast = document.createElement('div');
    toast.className = 'warning-toast';
    toast.innerHTML = `
      <span class="warning-icon">⏰</span>
      <span>${message}</span>
    `;
    document.body.appendChild(toast);
  }

  async logout() {
    clearInterval(this.countdownInterval);
    
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: {
          'CSRF-Token': this.csrfToken
        },
        credentials: 'include'
      });
    } catch (error) {
      console.error('Logout error');
    } finally {
      sessionStorage.clear();
      window.location.href = '/pages/login.html';
    }
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  new SecureCapture();
});
