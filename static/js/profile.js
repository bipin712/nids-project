// Profile Page Functionality

// Scroll to top button functionality
window.addEventListener('scroll', function() {
    const scrollBtn = document.getElementById('scrollToTopBtn');
    if (window.scrollY > 300) {
        scrollBtn.classList.add('show');
    } else {
        scrollBtn.classList.remove('show');
    }
});

function scrollToTop() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

// Modal management
function editProfile() {
    document.getElementById('editModal').classList.add('active');
}

function closeEditModal() {
    document.getElementById('editModal').classList.remove('active');
}

function saveProfile() {
    const name = document.getElementById('editName').value;
    const email = document.getElementById('editEmail').value;
    const mobile = document.getElementById('editMobile').value;
    
    if (!name || !email || !mobile) {
        alert('Please fill in all fields');
        return;
    }
    
    // Here you would typically make an API call to update the profile
    console.log('Profile updated:', { name, email, mobile });
    closeEditModal();
    // Reload page to reflect changes
    location.reload();
}

function changePassword() {
    alert('Password change feature coming soon!');
    // Implement password change functionality
}

function enable2FA() {
    alert('Two-Factor Authentication setup coming soon!');
    // Implement 2FA setup
}

function viewSessions() {
    alert('Session management coming soon!');
    // Implement session viewer
}

function deleteAccount() {
    const confirmDelete = confirm('Are you sure you want to permanently delete your account? This action cannot be undone.');
    
    if (confirmDelete) {
        const secondConfirm = confirm('Type "DELETE" to confirm account deletion.');
        if (secondConfirm) {
            alert('Account deletion feature coming soon!');
            // Implement account deletion
        }
    }
}

// Close modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('editModal');
    if (event.target === modal) {
        closeEditModal();
    }
}

// Load user profile data on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Profile page loaded');
});
