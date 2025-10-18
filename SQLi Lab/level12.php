<?php
// Level 12: JSON-based SQL Injection
// Goal: Exploit JSON parameter parsing in SQL queries

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
    $json_input = $_POST['json_data'] ?? '';
    
    try {
        // Parse JSON input
        $data = json_decode($json_input, true);
        
        if ($data === null) {
            $message = "Invalid JSON format!";
        } else {
            $username = $data['username'] ?? '';
            $password = $data['password'] ?? '';
            $role_filter = $data['role'] ?? 'user';
            
            // VULNERABLE query using JSON parsed data
            $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = '$role_filter'";
            
            $result = $conn->query($sql);
            
            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();
                
                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(12);
                    $message = "Great job! You exploited JSON-based SQL injection.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "JSON input: <code>" . htmlspecialchars($json_input) . "</code><br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access granted!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You need admin role to get the flag!";
                }
            } else {
                $message = "Authentication failed: no matching user found.";
                $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
            }
        }
        
    } catch (Exception $e) {
        $message = "JSON processing error: " . $e->getMessage();
        $message .= "<br>JSON input: <code>" . htmlspecialchars($json_input ?? 'N/A') . "</code>";
    }
}

// Sample JSON for reference
$sample_json = json_encode([
    'username' => 'guest',
    'password' => 'guest123', 
    'role' => 'user'
], JSON_PRETTY_PRINT);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 12 - JSON Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .json-container {
            max-width: 700px;
            margin: 2rem auto;
            background: #1e1b4b;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(30, 27, 75, 0.4);
            border: 1px solid #6366f1;
        }
        
        .json-viewer {
            background: #0f0f23;
            border: 2px solid #4f46e5;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #a5b4fc;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            white-space: pre;
        }
        
        .form-group textarea {
            background: #0f0f23;
            color: #e2e8f0;
            border: 2px solid #4f46e5;
            min-height: 120px;
            font-family: 'JetBrains Mono', monospace;
            resize: vertical;
        }
        
        .form-group textarea:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
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
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
        }
        
        .json-info {
            background: #0f0f23;
            border: 2px solid #6366f1;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #a5b4fc;
        }
        
        .sample-btn {
            background: #374151;
            color: #e2e8f0;
            border: 1px solid #6b7280;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        .sample-btn:hover {
            background: #4b5563;
        }
        
        body {
            background: linear-gradient(135deg, #0f0f23 0%, #1e1b4b 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 12 - JSON Injection</h1>
            <p>Exploit JSON parameter parsing vulnerabilities in API authentication</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>
        
        <div class="json-container">
            <div class="json-info">
                <h4> JSON Injection Challenge</h4>
                <p>This API accepts JSON authentication data and processes it in SQL queries.</p>
                <p><strong>Goal:</strong> Manipulate JSON parameters to login as admin!</p>
            </div>
            
            <div class="json-viewer"><?= htmlspecialchars($sample_json) ?></div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3> JSON Authentication API</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="json_data">JSON Data:</label>
                    <textarea id="json_data" name="json_data" 
                              placeholder="Enter JSON authentication data..." required><?= htmlspecialchars($sample_json) ?></textarea>
                    <button type="button" class="sample-btn" onclick="loadSampleJSON()">Load Sample JSON</button>
                </div>
                
                <button type="submit" class="submit-btn">Authenticate</button>
            </form>
        </div>
        
        <?= render_hint_section(get_level_hints(12), 'Hints for Level 12'); ?>
        
        <div class="navigation">
            <a href="level11.php">&larr; Previous Level</a>
            <a href="level13.php">Next Level &rarr;</a>
        </div>
    </div>
    
    <script>
        function loadSampleJSON() {
            document.getElementById('json_data').value = `{
    "username": "guest",
    "password": "guest123",
    "role": "user"
}`;
        }
    </script>
</body>
</html>

<?php $conn->close(); ?>


