# AuthServerJacks

A lightweight, secure authentication server for JackBotGUI, designed to run efficiently on low-resource Linux Google Compute Engine instances.

## Features

- Lightweight and performant using Axum web framework
- SQLite database for user storage
- Role-based authentication (admin and user roles)
- JWT-based authentication
- Secure password hashing with bcrypt
- Configurable via environment variables

## API Endpoints

- `GET /` - Server status check
- `POST /admin/login` - Admin login
- `POST /admin/add-user` - Add a new user (admin protected)
- `POST /login` - User login

## Setup & Deployment

### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))
- SQLite (usually pre-installed on Linux)

### Local Development

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/auth_server_jacks.git
   cd auth_server_jacks
   ```

2. Create a `.env` file based on the example:
   ```
   cp .env.example .env
   ```

3. Edit the `.env` file with your secure credentials:
   ```
   # Use strong passwords and a secure JWT secret!
   ADMIN_USERNAME=your_admin_username
   ADMIN_PASSWORD=your_secure_admin_password
   JWT_SECRET=your_random_jwt_secret
   ```

4. Build and run the server:
   ```
   cargo build --release
   cargo run --release
   ```

### Deployment to Google Compute Engine

1. Build the project for Linux (if not already on Linux):
   ```
   cargo build --release
   ```
   
2. Transfer the compiled binary to your GCE instance:
   ```
   scp target/release/auth_server_jacks your-username@your-instance-ip:~/
   ```

3. Set up the environment variables on your server:
   ```
   # On the server
   echo 'export DATABASE_URL=sqlite:auth.db' >> ~/.bashrc
   echo 'export PORT=3000' >> ~/.bashrc
   echo 'export ADMIN_USERNAME=your_admin_username' >> ~/.bashrc
   echo 'export ADMIN_PASSWORD=your_secure_admin_password' >> ~/.bashrc
   echo 'export JWT_SECRET=your_random_jwt_secret' >> ~/.bashrc
   echo 'export JWT_EXPIRY_HOURS=24' >> ~/.bashrc
   echo 'export RUST_LOG=info' >> ~/.bashrc
   source ~/.bashrc
   ```

4. Run the server in the background:
   ```
   nohup ./auth_server_jacks > server.log 2>&1 &
   ```

### Systemd Service (Recommended for Production)

1. Create a systemd service file:
   ```
   sudo nano /etc/systemd/system/auth-server.service
   ```

2. Add the following content:
   ```
   [Unit]
   Description=Auth Server for JackBotGUI
   After=network.target

   [Service]
   Type=simple
   User=your-username
   WorkingDirectory=/home/your-username
   ExecStart=/home/your-username/auth_server_jacks
   Restart=on-failure
   Environment="DATABASE_URL=sqlite:auth.db"
   Environment="PORT=3000"
   Environment="ADMIN_USERNAME=your_admin_username"
   Environment="ADMIN_PASSWORD=your_secure_admin_password"
   Environment="JWT_SECRET=your_random_jwt_secret"
   Environment="JWT_EXPIRY_HOURS=24"
   Environment="RUST_LOG=info"

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```
   sudo systemctl enable auth-server
   sudo systemctl start auth-server
   ```

4. Check the service status:
   ```
   sudo systemctl status auth-server
   ```

## API Usage Examples

### Admin Login
