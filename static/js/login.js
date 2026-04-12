// Login page functionality
const form = document.getElementById('loginForm');
const alertDiv = document.getElementById('alert');

// Check for remembered email
if (localStorage.getItem('remembered_email')) {
    const emailInput = document.getElementById('email');
    const rememberCheck = document.getElementById('remember');
    if (emailInput && rememberCheck) {
        emailInput.value = localStorage.getItem('remembered_email');
        rememberCheck.checked = true;
    }
}

function validateEmail(email) {
    const error = document.getElementById('emailError');
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
        if (error) error.classList.add('show');
        return false;
    }
    if (error) error.classList.remove('show');
    return true;
}

function validatePassword(password) {
    const error = document.getElementById('passwordError');
    if (password.length === 0) {
        if (error) error.classList.add('show');
        return false;
    }
    if (error) error.classList.remove('show');
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
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember').checked;
        
        if (!validateEmail(email) || !validatePassword(password)) {
            showAlert('Please enter valid credentials', 'error');
            return;
        }
        
        // Handle remember me
        if (remember) {
            localStorage.setItem('remembered_email', email);
        } else {
            localStorage.removeItem('remembered_email');
        }
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    password: password
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                showAlert(data.message, 'success');
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 1000);
            } else {
                showAlert(data.message, 'error');
            }
        } catch (error) {
            showAlert('Network error. Please try again.', 'error');
        }
    });
    
    // Add Enter key support
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                form.dispatchEvent(new Event('submit'));
            }
        });
    }
}