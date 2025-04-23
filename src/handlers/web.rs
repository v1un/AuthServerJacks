use crate::error::Result;
use crate::AppState;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use std::fs;
use std::sync::Arc;

// Read an HTML template file
fn read_template(template_name: &str) -> std::io::Result<String> {
    let template_path = format!("templates/{}.html", template_name);
    fs::read_to_string(&template_path)
}

// Main index page
pub async fn index() -> impl IntoResponse {
    let template = match read_template("index") {
        Ok(content) => content,
        Err(_) => "<h1>Auth Server</h1><p>Welcome to the Auth Server. <a href='/admin/login'>Admin Login</a></p>".to_string(),
    };
    
    Html(template)
}

// Admin login page
pub async fn admin_login_page() -> impl IntoResponse {
    let template = match read_template("admin_login") {
        Ok(content) => content,
        Err(_) => "<h1>Admin Login</h1><form method='post' action='/api/admin/login'><input name='username' placeholder='Username'><input type='password' name='password' placeholder='Password'><button type='submit'>Login</button></form>".to_string(),
    };
    
    Html(template)
}

// Admin dashboard page (requires admin auth)
pub async fn admin_dashboard(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let template = match read_template("admin_dashboard") {
        Ok(content) => content,
        Err(_) => {
            let html = r#"
            <h1>Admin Dashboard</h1>
            <nav>
                <a href="/admin/users">Manage Users</a>
                <a href="/admin/add-user">Add New User</a>
                <a href="#" onclick="logout()">Logout</a>
            </nav>
            <script>
                function logout() {
                    localStorage.removeItem('adminToken');
                    window.location.href = '/admin/login';
                }
            </script>
            "#;
            html.to_string()
        }
    };
    
    Html(template)
}

// Admin users page (requires admin auth)
pub async fn admin_users_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let template = match read_template("admin_users") {
        Ok(content) => content,
        Err(_) => {
            let html = r#"
            <h1>User Management</h1>
            <div id="usersList">Loading users...</div>
            <script>
                document.addEventListener('DOMContentLoaded', async () => {
                    const token = localStorage.getItem('adminToken');
                    if (!token) {
                        window.location.href = '/admin/login';
                        return;
                    }
                    
                    try {
                        const response = await fetch('/api/admin/users', {
                            headers: {
                                'Authorization': `Bearer ${token}`
                            }
                        });
                        
                        if (response.ok) {
                            const users = await response.json();
                            let html = '<table border="1"><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th>Actions</th></tr>';
                            
                            users.forEach(user => {
                                html += `<tr>
                                    <td>${user.id}</td>
                                    <td>${user.username}</td>
                                    <td>${user.role}</td>
                                    <td>${new Date(user.created_at).toLocaleString()}</td>
                                    <td>
                                        <button onclick="deleteUser(${user.id})">Delete</button>
                                    </td>
                                </tr>`;
                            });
                            
                            html += '</table>';
                            document.getElementById('usersList').innerHTML = html;
                        } else {
                            document.getElementById('usersList').innerHTML = 'Failed to load users. Please try again.';
                        }
                    } catch (error) {
                        document.getElementById('usersList').innerHTML = 'Error loading users: ' + error.message;
                    }
                });
                
                async function deleteUser(userId) {
                    if (!confirm('Are you sure you want to delete this user?')) return;
                    
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
                            location.reload();
                        } else {
                            const error = await response.json();
                            alert(`Failed to delete user: ${error.error}`);
                        }
                    } catch (error) {
                        alert('Error: ' + error.message);
                    }
                }
            </script>
            "#;
            html.to_string()
        }
    };
    
    Html(template)
}

// Admin add user page (requires admin auth)
pub async fn admin_add_user_page() -> impl IntoResponse {
    let template = match read_template("admin_add_user") {
        Ok(content) => content,
        Err(_) => {
            let html = r#"
            <h1>Add New User</h1>
            <form id="addUserForm">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required minlength="8">
                </div>
                <button type="submit">Add User</button>
            </form>
            <div id="message"></div>
            <p><a href="/admin/users">Back to Users</a></p>
            
            <script>
                document.addEventListener('DOMContentLoaded', () => {
                    const token = localStorage.getItem('adminToken');
                    if (!token) {
                        window.location.href = '/admin/login';
                        return;
                    }
                    
                    document.getElementById('addUserForm').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        const username = document.getElementById('username').value;
                        const password = document.getElementById('password').value;
                        
                        try {
                            const response = await fetch('/api/admin/add-user', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${token}`
                                },
                                body: JSON.stringify({ username, password })
                            });
                            
                            const result = await response.json();
                            
                            if (response.ok) {
                                document.getElementById('message').innerHTML = `<div style="color: green">${result.message}</div>`;
                                document.getElementById('username').value = '';
                                document.getElementById('password').value = '';
                            } else {
                                document.getElementById('message').innerHTML = `<div style="color: red">Error: ${result.error}</div>`;
                            }
                        } catch (error) {
                            document.getElementById('message').innerHTML = `<div style="color: red">Error: ${error.message}</div>`;
                        }
                    });
                });
            </script>
            "#;
            html.to_string()
        }
    };
    
    Html(template)
}