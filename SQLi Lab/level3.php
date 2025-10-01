<?php
// Level 3: Stacked Query Login - Multiple SQL Statements
// Goal: Use stacked queries to modify data and login as admin

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
    
    // Only check if user exists first, then allow stacked queries for manipulation
    $check_sql = "SELECT COUNT(*) as count FROM users WHERE username = '$username'";
    $check_result = $conn->query($check_sql);
    $user_exists = $check_result && $check_result->fetch_assoc()['count'] > 0;
    
    if (!$user_exists) {
        $message = "❌ User does not exist. Try creating an admin account first.";
    } else {
        // Vulnerable to stacked queries - allows multiple statements  
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            // Enable multi_query to allow stacked queries
            if ($conn->multi_query($sql)) {
                do {
                    if ($result = $conn->store_result()) {
                        if ($result->num_rows > 0) {
                            $user_data = $result->fetch_assoc();
                            if ($user_data['role'] === 'admin') {
                                $success = true;
                                $message = "🎉 Outstanding! You used stacked queries to login as admin!<br>";
                                $message .= "🏁 <strong>FLAG: LEVEL3_STACKED_QUERY_MASTERY</strong><br>";
                                $message .= "Admin User: " . htmlspecialchars($user_data['username']);
                            } else {
                                $message = "✅ Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                            }
                        }
                        $result->free();
                    }
                } while ($conn->next_result());
                
                if (!$success && !$message) {
                    $message = "❌ Login failed: Invalid password. Try modifying the user's role or password first.";
                }
            }
        } catch (Exception $e) {
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
    <title>Level 3 - Stacked Query Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .login-container {
            max-width: 600px;
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
        
        .warning-box {
            background: #fffaf0;
            border: 2px solid #f6ad55;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .warning-box h4 {
            color: #c05621;
            margin: 0 0 0.5rem 0;
        }
        
        .warning-box p {
            color: #744210;
            margin: 0;
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
        
        .code-example {
            background: #1a202c;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 0.5rem 0;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Level 3 - Stacked Query Login</h1>
            <p>Execute multiple SQL statements in a single injection attack</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🏭 Industrial Control Login</h2>
            <p><strong>Objective:</strong> Use stacked queries to modify database and gain admin access</p>
            
            <div class="warning-box">
                <h4>⚠️ Advanced Challenge</h4>
                <p>This system allows multiple SQL statements. You can INSERT, UPDATE, or even CREATE new admin accounts!</p>
            </div>
            
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
            <h3>💡 Hints for Level 3:</h3>
            <ul>
                <li><strong>Prerequisite:</strong> User must exist first (try: test, alice, bob)</li>
                <li><strong>Stacked Queries:</strong> Use <code>;</code> to separate multiple SQL statements</li>
                <li><strong>Method 1:</strong> Promote existing user to admin</li>
            </ul>
            <div class="code-example">test'; UPDATE users SET role='admin' WHERE username='test';--</div>
            <ul>
                <li><strong>Method 2:</strong> Change existing user password then login</li>
            </ul>
            <div class="code-example">test'; UPDATE users SET password='newpass' WHERE username='test';--</div>
            <ul>
                <li><strong>Method 3:</strong> Create new admin (if username doesn't exist, create it first)</li>
            </ul>
            <div class="code-example">newuser'; INSERT INTO users VALUES(NULL,'newuser','pass','admin');--</div>
            <p><strong>Remember:</strong> After modifying, login with the updated credentials!</p>
        </div>
        
        <div class="navigation">
            <a href="level2.php">← Previous Level</a>
            <a href="level4.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>