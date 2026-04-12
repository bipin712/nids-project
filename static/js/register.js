// Register page functionality
const form = document.getElementById('registerForm');
const alertDiv = document.getElementById('alert');

// Password strength checker
const passwordInput = document.getElementById('password');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

if (passwordInput) {
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        let strength = 0;
        
        if (password.length >= 6) strength++;
        if (password.length >= 10) strength++;
        if (password.match(/[a-z]/) && password.match(/[A-Z]/)) strength++;
        if (password.match(/[0-9]/)) strength++;
        if (password.match(/[^a-zA-Z0-9]/)) strength++;
        
        const percentage = (strength / 5) * 100;
        strengthBar.style.width = percentage + '%';
        
        if (percentage <= 20) {
            strengthBar.style.background = '#e74c3c';
            strengthText.textContent = 'Weak password';
        } else if (percentage <= 40) {
            strengthBar.style.background = '#f39c12';
            strengthText.textContent = 'Fair password';
        } else if (percentage <= 60) {
            strengthBar.style.background = '#3498db';
            strengthText.textContent = 'Good password';
        } else if (percentage <= 80) {
            strengthBar.style.background = '#2ecc71';
            strengthText.textContent = 'Strong password';
        } else {
            strengthBar.style.background = '#27ae60';
            strengthText.textContent = 'Very strong password';
        }
    });
}

// Real-time validation
const nameInput = document.getElementById('name');
const emailInput = document.getElementById('email');
const mobileInput = document.getElementById('mobile');
const confirmInput = document.getElementById('confirm_password');

if (nameInput) {
    nameInput.addEventListener('input', function() {
        validateName(this.value);
    });
}

if (emailInput) {
    emailInput.addEventListener('input', function() {
        validateEmail(this.value);
    });
}

if (mobileInput) {
    mobileInput.addEventListener('input', function() {
        validateMobile(this.value);
    });
}

if (confirmInput) {
    confirmInput.addEventListener('input', function() {
        validateConfirmPassword();
    });
}

function validateName(name) {
    const error = document.getElementById('nameError');
    if (name.trim().length < 2) {
        error.classList.add('show');
        return false;
    }
    error.classList.remove('show');
    return true;
}

function validateEmail(email) {
    const error = document.getElementById('emailError');
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
        error.classList.add('show');
        return false;
    }
    error.classList.remove('show');
    return true;
}

function validateMobile(mobile) {
    const error = document.getElementById('mobileError');
    const mobileRegex = /^[0-9]{10}$/;
    if (!mobileRegex.test(mobile)) {
        error.classList.add('show');
        return false;
    }
    error.classList.remove('show');
    return true;
}

function validateConfirmPassword() {
    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm_password').value;
    const error = document.getElementById('confirmError');
    
    if (password !== confirm) {
        error.classList.add('show');
        return false;
    }
    error.classList.remove('show');
    return true;
}

function showAlert(message, type) {
    alertDiv.textContent = message;
    alertDiv.className = `alert alert-${type}`;
    alertDiv.style.display = 'block';
    
    setTimeout(() => {
        alertDiv.style.display = 'none';
    }, 5000);
}

if (form) {
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const mobile = document.getElementById('mobile').value;
        const password = document.getElementById('password').value;
        const confirm = document.getElementById('confirm_password').value;
        
        if (!validateName(name) || !validateEmail(email) || !validateMobile(mobile)) {
            showAlert('Please fill all fields correctly', 'error');
            return;
        }
        
        if (password.length < 6) {
            showAlert('Password must be at least 6 characters', 'error');
            return;
        }
        
        if (password !== confirm) {
            showAlert('Passwords do not match', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    email: email,
                    mobile: mobile,
                    password: password,
                    confirm_password: confirm
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert(data.message, 'success');
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1500);
            } else {
                showAlert(data.message, 'error');
            }
        } catch (error) {
            showAlert('Network error. Please try again.', 'error');
        }
    });
}