<?php
// Level 1: Basic Login Form - Error Based SQL Injection
// Goal: Login as admin using SQL injection

require_once __DIR__ . '/includes/helpers.php';

mysqli_report(MYSQLI_REPORT_OFF);

$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp';
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}

$message = '';
$success = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Vulnerable SQL query - directly concatenates user input
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    try {
        $result = $conn->query($sql);

        if ($result && $result->num_rows > 0) {
            $userData = $result->fetch_assoc();
            if (($userData['role'] ?? '') === 'admin') {
                $success = true;
                $flag = get_flag_for_level(1);
                $message = "Great job! You successfully logged in as admin.<br>";
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                $message .= "Username: " . htmlspecialchars($userData['username']) . "<br>";
                $message .= "Role: " . htmlspecialchars($userData['role']);
            } else {
                $message = "Login successful, but you still need the admin account.<br>";
                $message .= "Current user: " . htmlspecialchars($userData['username']) . " (" . htmlspecialchars($userData['role'] ?? 'user') . ")";
            }
        } else {
            $message = "Login failed: Invalid username or password.";
        }
    } catch (Exception $e) {
        $message = "Database error: " . $e->getMessage();
        $message .= "<br><br>SQL Query: " . htmlspecialchars($sql);
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
            max-width: 480px;
            margin: 2rem auto;
            background: #faf7f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
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
            transition: border-color 0.3s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: #3182ce;
            box-shadow: 0 0 0 3px rgba(49, 130, 206, 0.15);
        }

        .login-btn {
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
            color: #ffffff;
            padding: 0.9rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 18px rgba(66, 153, 225, 0.32);
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
            background: #fff5f5;
            border-color: #e53e3e;
            color: #c53030;
        }

        .message.info {
            background: #ebf8ff;
            border-color: #3182ce;
            color: #2c5282;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 1 - Basic Login</h1>
            <p>Your first SQL injection challenge. Error messages will help you map the query.</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="login-container">
            <h2>Admin Login Portal</h2>
            <p><strong>Objective:</strong> log in as the <code>admin</code> user by abusing SQL injection.</p>

            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>

                <button type="submit" class="login-btn">Login</button>
            </form>
        </div>

        <?= render_hint_section(get_level_hints(1), 'Hints for Level 1'); ?>

        <div class="navigation">
            <a href="level2.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>
<?php $conn->close(); ?>


