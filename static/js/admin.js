// Admin interface JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Check for authentication 
    const adminToken = localStorage.getItem('adminToken');
    const currentPath = window.location.pathname;
    
    // If not on login page and no token, redirect to login
    if (!currentPath.includes('/admin/login') && !adminToken) {
        window.location.href = '/admin/login';
        return;
    }
    
    // Setup login form if on login page
    if (currentPath.includes('/admin/login')) {
        setupLoginForm();
    }
    
    // Setup users table if on users page
    if (currentPath.includes('/admin/users')) {
        loadUsers();
    }
    
    // Setup add user form if on add user page
    if (currentPath.includes('/admin/add-user')) {
        setupAddUserForm();
    }
});

// Handle admin login
function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    if (!loginForm) return;
    
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const messageEl = document.getElementById('message');
        
        if (!username || !password) {
            showMessage(messageEl, 'Please enter both username and password', 'error');
            return;
        }
        
        try {
            const response = await fetch('/api/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token and redirect
                localStorage.setItem('adminToken', data.token);
                showMessage(messageEl, 'Login successful! Redirecting...', 'success');
                setTimeout(() => {
                    window.location.href = '/admin';
                }, 1000);
            } else {
                showMessage(messageEl, data.error || 'Login failed', 'error');
            }
        } catch (error) {
            showMessage(messageEl, 'An error occurred: ' + error.message, 'error');
        }
    });
}

// Load users for the admin panel
async function loadUsers() {
    const usersList = document.getElementById('usersList');
    if (!usersList) return;
    
    const token = localStorage.getItem('adminToken');
    
    try {
        const response = await fetch('/api/admin/users', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const users = await response.json();
            
            if (users.length === 0) {
                usersList.innerHTML = '<p>No users found</p>';
                return;
            }
            
            let html = `
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            users.forEach(user => {
                const createdDate = new Date(user.created_at).toLocaleString();
                html += `
                    <tr>
                        <td>${user.id}</td>
                        <td>${user.username}</td>
                        <td>${user.role}</td>
                        <td>${createdDate}</td>
                        <td>
                            <button class="btn btn-danger btn-sm" onclick="deleteUser(${user.id})">Delete</button>
                        </td>
                    </tr>
                `;
            });
            
            html += `
                    </tbody>
                </table>
            `;
            
            usersList.innerHTML = html;
        } else {
            const error = await response.json();
            usersList.innerHTML = `<div class="alert alert-danger">Error: ${error.error || 'Failed to load users'}</div>`;
        }
    } catch (error) {
        usersList.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
    }
}

// Delete a user
async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }
    
    const token = localStorage.getItem('adminToken');
    
    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            alert('User deleted successfully');
            loadUsers(); // Reload the user list
        } else {
            const error = await response.json();
            alert(`Error: ${error.error || 'Failed to delete user'}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// Set up the add user form
function setupAddUserForm() {
    const addUserForm = document.getElementById('addUserForm');
    if (!addUserForm) return;
    
    addUserForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const messageEl = document.getElementById('message');
        
        if (!username || !password) {
            showMessage(messageEl, 'Please enter both username and password', 'error');
            return;
        }
        
        if (password.length < 8) {
            showMessage(messageEl, 'Password must be at least 8 characters long', 'error');
            return;
        }
        
        const token = localStorage.getItem('adminToken');
        
        try {
            const response = await fetch('/api/admin/add-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showMessage(messageEl, data.message || 'User added successfully', 'success');
                // Clear the form
                addUserForm.reset();
            } else {
                showMessage(messageEl, data.error || 'Failed to add user', 'error');
            }
        } catch (error) {
            showMessage(messageEl, 'An error occurred: ' + error.message, 'error');
        }
    });
}

// Logout function
function logout() {
    localStorage.removeItem('adminToken');
    window.location.href = '/admin/login';
}

// Helper to display messages
function showMessage(element, message, type) {
    if (!element) return;
    
    element.textContent = message;
    element.className = ''; // Remove all classes
    
    if (type === 'error') {
        element.classList.add('alert', 'alert-danger');
    } else if (type === 'success') {
        element.classList.add('alert', 'alert-success');
    } else if (type === 'warning') {
        element.classList.add('alert', 'alert-warning');
    }
    
    element.style.display = 'block';
}
