<?php
// Level 1: Basic Login Form - Error Based SQL Injection
// Goal: Login as admin using SQL injection

// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'root'; 
$pass = $_ENV['DB_PASS'] ?? 'rootpassword';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
$success = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Vulnerable SQL query - directly concatenating user input
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    try {
        $result = $conn->query($sql);
        
        if ($result && $result->num_rows > 0) {
            $user_data = $result->fetch_assoc();
            if ($user_data['role'] === 'admin') {
                $success = true;
                $message = "🎉 Congratulations! You successfully logged in as admin!<br>";
                $message .= "🏁 <strong>FLAG: LEVEL1_BASIC_LOGIN_BYPASS</strong><br>";
                $message .= "Username: " . htmlspecialchars($user_data['username']) . "<br>";
                $message .= "Role: " . htmlspecialchars($user_data['role']);
            } else {
                $message = "✅ Login successful, but you need to login as admin!<br>";
                $message .= "Current user: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
            }
        } else {
            $message = "❌ Login failed: Invalid username or password";
        }
    } catch (Exception $e) {
        // Show SQL error to help with injection
        $message = "💥 Database Error: " . $e->getMessage();
        $message .= "<br><br>📝 SQL Query: " . htmlspecialchars($sql);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Basic Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .login-container {
            max-width: 500px;
            margin: 2rem auto;
            background: #faf7f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
        }
        
        .login-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        
        .form-group label {
            font-weight: 600;
            color: #2c2c2c;
        }
        
        .form-group input {
            padding: 0.8rem;
            border: 2px solid #e8dcc6;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #4299e1;
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1);
        }
        
        .login-btn {
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: white;
            padding: 1rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(66, 153, 225, 0.4);
        }
        
        .message {
            margin: 1rem 0;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid;
        }
        
        .message.success {
            background: #f0fff4;
            border-color: #38a169;
            color: #2f855a;
        }
        
        .message.error {
            background: #fed7d7;
            border-color: #e53e3e;
            color: #c53030;
        }
        
        .message.info {
            background: #ebf8ff;
            border-color: #3182ce;
            color: #2c5282;
        }
        
        .hints {
            background: #f7fafc;
            padding: 1.5rem;
            border-radius: 8px;
            margin-top: 2rem;
            border: 2px solid #e2e8f0;
        }
        
        .hints h3 {
            color: #2d3748;
            margin-bottom: 1rem;
        }
        
        .hints ul {
            margin: 0;
            padding-left: 1.5rem;
        }
        
        .hints li {
            margin-bottom: 0.5rem;
            color: #4a5568;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Level 1 - Basic Login</h1>
            <p>Your first SQL injection challenge! This login form shows error messages that can help you.</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🔐 Admin Login Portal</h2>
            <p><strong>Objective:</strong> Login as 'admin' user using SQL injection</p>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (strpos($message, 'Error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="login-btn">🚀 Login</button>
            </form>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 1:</h3>
            <ul>
                <li><strong>Start Simple:</strong> Try basic payloads like <code>' OR '1'='1</code></li>
                <li><strong>Read Errors:</strong> SQL error messages will show you the exact query structure</li>
                <li><strong>Comment Out:</strong> Use <code>--</code> or <code>#</code> to comment out the rest of the query</li>
                <li><strong>Test Goal:</strong> You need to login as 'admin' specifically, not just any user</li>
                <li><strong>Try:</strong> <code>admin'--</code> in username field (ignore password)</li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level2.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>