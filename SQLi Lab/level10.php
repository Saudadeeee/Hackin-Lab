<?php
// Level 10: INSERT Injection - User Registration
// Goal: Exploit INSERT statement to become admin during registration

session_start();

require_once __DIR__ . '/includes/helpers.php';
// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp'; 
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
$success = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $email = $_POST['email'] ?? '';
    $fullname = $_POST['fullname'] ?? '';
    $phone = $_POST['phone'] ?? '';
    
    // VULNERABLE INSERT query - directly concatenating user input
    $sql = "INSERT INTO users (username, password, email, role) VALUES ('$username', 'defaultpass', '$email', 'user')";
    
    try {
        // Execute the INSERT query
        if ($conn->query($sql)) {
            $user_id = $conn->insert_id;
            
            // Check if the newly created user is admin
            $check_sql = "SELECT * FROM users WHERE id = $user_id";
            $result = $conn->query($check_sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(10);
                    $message = "Great job! You exploited INSERT injection to become admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "User ID: " . $user_data['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($user_data['username']) . "<br>";
                    $message .= "Role: " . htmlspecialchars($user_data['role']) . "<br>";
                    $message .= "INSERT query: <code>" . htmlspecialchars($sql) . "</code>";
                } else {
                    $message = "User registered successfully!<br>";
                    $message .= "User ID: " . $user_data['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($user_data['username']) . "<br>";
                    $message .= "Role: " . htmlspecialchars($user_data['role']) . "<br>";
                    $message .= "You need to become admin to get the flag!";
                }
            }
        } else {
            $message = "Registration failed: " . $conn->error;
            $message .= "<br> INSERT Query: <code>" . htmlspecialchars($sql) . "</code>";
        }
        
    } catch (Exception $e) {
        $message = "INSERT Error: " . $e->getMessage();
        $message .= "<br> INSERT Query: <code>" . htmlspecialchars($sql) . "</code>";
        $message .= "<br> Error might indicate successful injection!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 - INSERT Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .insert-container {
            max-width: 650px;
            margin: 2rem auto;
            background: #2a1810;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(42, 24, 16, 0.4);
            border: 1px solid #ea580c;
        }
        
        .form-group input {
            background: #1a0f0a;
            color: #e2e8f0;
            border: 2px solid #ea580c;
        }
        
        .form-group input:focus {
            border-color: #f97316;
            box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
            color: white;
            padding: 1rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .submit-btn:hover {
            box-shadow: 0 6px 20px rgba(249, 115, 22, 0.4);
        }
        
        .insert-info {
            background: #1a0f0a;
            border: 2px solid #ea580c;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fb923c;
        }
        
        .sql-structure {
            background: #1a0f0a;
            border: 2px solid #f97316;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #fdba74;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }
        
        body {
            background: linear-gradient(135deg, #1a0f0a 0%, #2a1810 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 10 - INSERT Injection</h1>
            <p>Exploit INSERT statement vulnerabilities during user registration</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>
        
        <div class="insert-container">
            <div class="insert-info">
                <h4> INSERT Injection Challenge</h4>
                <p>Manipulate the INSERT query to register as an admin user!</p>
                <p><strong>Goal:</strong> Become admin during registration process</p>
            </div>
            
            <div class="sql-structure">
                <strong>INSERT Query Structure:</strong><br>
                INSERT INTO users (username, password, email, role) <br>
                VALUES ('$username', 'defaultpass', '$email', 'user')
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3> User Registration</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" placeholder="Enter username (vulnerable field!)" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" placeholder="Enter email address" required>
                </div>
                
                <div class="form-group">
                    <label for="fullname">Full Name:</label>
                    <input type="text" id="fullname" name="fullname" placeholder="Enter full name">
                </div>
                
                <div class="form-group">
                    <label for="phone">Phone:</label>
                    <input type="text" id="phone" name="phone" placeholder="Enter phone number">
                </div>
                
                <button type="submit" class="submit-btn">Register Account</button>
            </form>
        </div>
        
        <?= render_hint_section(get_level_hints(10), 'Hints for Level 10'); ?>
        
        <div class="navigation">
            <a href="level9.php">&larr; Previous Level</a>
            <a href="level11.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>



