<?php
// Level 2: Union Based Login Form - Extract Data via UNION
// Goal: Login as admin and extract sensitive data using UNION attacks

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
$user_data = null;

if ($_POST) {
    $user_id = $_POST['user_id'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Integer-based injection - no quotes around user_id
    $sql = "SELECT id, username, role FROM users WHERE id = $user_id AND password = '$password'";
    
    try {
        $result = $conn->query($sql);
        
        if ($result && $result->num_rows > 0) {
            $user_data = $result->fetch_all(MYSQLI_ASSOC);
            
            // Check if admin was found
            $admin_found = false;
            foreach ($user_data as $user) {
                if ($user['role'] === 'admin' || $user['username'] === 'admin') {
                    $admin_found = true;
                    break;
                }
            }
            
            if ($admin_found) {
                $success = true;
                $message = "🎉 Excellent! You successfully used integer injection with UNION to get admin!<br>";
                $message .= "🏁 <strong>FLAG: LEVEL2_INTEGER_UNION_INJECTION</strong>";
            } else {
                $message = "✅ Data extracted, but no admin found. Try UNION SELECT to inject admin data.";
            }
        } else {
            $message = "❌ Login failed: Invalid credentials";
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
    <title>Level 2 - Union Login | SQL Injection Lab</title>
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
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .data-table th {
            background: #4299e1;
            color: white;
            padding: 1rem;
            text-align: left;
        }
        
        .data-table td {
            padding: 0.8rem 1rem;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .data-table tr:hover {
            background: #f7fafc;
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
            <h1>🔗 Level 2 - Union Login</h1>
            <p>Use UNION SELECT to extract data from other tables and login as admin</p>
            <a href="index.php" class="back-btn">← Back to Labs</a>
        </div>
        
        <div class="login-container">
            <h2>🏢 Corporate Login System</h2>
            <p><strong>Objective:</strong> Use UNION injection to extract admin credentials and login successfully</p>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (strpos($message, 'Error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="user_id">User ID:</label>
                    <input type="text" id="user_id" name="user_id" placeholder="Enter user ID (number)" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="login-btn">🚀 Login</button>
            </form>
            
            <?php if ($user_data && count($user_data) > 0): ?>
                <h3>📊 Extracted Data:</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($user_data as $user): ?>
                            <tr>
                                <td><?= htmlspecialchars($user['id'] ?? 'N/A') ?></td>
                                <td><?= htmlspecialchars($user['username'] ?? 'N/A') ?></td>
                                <td><?= htmlspecialchars($user['role'] ?? 'N/A') ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
        
        <div class="hints">
            <h3>💡 Hints for Level 2:</h3>
            <ul>
                <li><strong>Integer Injection:</strong> This level uses numeric user ID without quotes</li>
                <li><strong>UNION Attack:</strong> Use <code>UNION SELECT</code> to inject data</li>
                <li><strong>Column Count:</strong> First find number of columns: <code>1 ORDER BY 3</code></li>
                <li><strong>Try:</strong> <code>999 UNION SELECT 1,'admin','admin'</code> in user ID field</li>
                <li><strong>Admin ID:</strong> Admin user has ID = 3, so try: <code>3</code> with password <code>admin123</code></li>
                <li><strong>Advanced:</strong> <code>1 UNION SELECT 999,'admin','admin'</code></li>
            </ul>
        </div>
        
        <div class="navigation">
            <a href="level1.php">← Previous Level</a>
            <a href="level3.php">Next Level →</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>