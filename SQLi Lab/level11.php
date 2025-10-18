<?php
// Level 11: UPDATE Injection - Profile Update System
// Goal: Exploit UPDATE statement to escalate privileges to admin

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
$current_user = null;

// Initialize session with default user if not set
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = 2; // guest user
}

// Get current user info
$user_sql = "SELECT * FROM users WHERE id = " . $_SESSION['user_id'];
$user_result = $conn->query($user_sql);
if ($user_result && $user_result->num_rows > 0) {
    $current_user = $user_result->fetch_assoc();
}

if ($_POST) {
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $bio = $_POST['bio'] ?? '';
    $website = $_POST['website'] ?? '';
    
    $user_id = $_SESSION['user_id'];
    
    // VULNERABLE UPDATE query - directly concatenating user input
    $sql = "UPDATE users SET email = '$email', phone = '$phone', bio = '$bio', website = '$website' WHERE id = $user_id";
    
    try {
        // Execute the UPDATE query
        if ($conn->query($sql)) {
            // Get updated user info
            $check_sql = "SELECT * FROM users WHERE id = $user_id";
            $result = $conn->query($check_sql);
            
            if ($result && $result->num_rows > 0) {
                $updated_user = $result->fetch_assoc();
                
                if ($updated_user['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(11);
                    $message = "Great job! You exploited UPDATE injection to escalate privileges.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "User ID: " . $updated_user['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($updated_user['username']) . "<br>";
                    $message .= "New role: " . htmlspecialchars($updated_user['role']) . "<br>";
                    $message .= "UPDATE query: <code>" . htmlspecialchars($sql) . "</code>";
                } else {
                    $message = "Profile updated successfully!<br>";
                    $message .= "Username: " . htmlspecialchars($updated_user['username']) . "<br>";
                    $message .= "Email: " . htmlspecialchars($updated_user['email']) . "<br>";
                    $message .= " Role: " . htmlspecialchars($updated_user['role']) . "<br>";
                    $message .= " You need to escalate to admin role to get the flag!";
                }
                
                $current_user = $updated_user; // Update display
            }
        } else {
            $message = " Profile update failed: " . $conn->error;
            $message .= "<br> UPDATE Query: <code>" . htmlspecialchars($sql) . "</code>";
        }
        
    } catch (Exception $e) {
        $message = " UPDATE Error: " . $e->getMessage();
        $message .= "<br> UPDATE Query: <code>" . htmlspecialchars($sql) . "</code>";
        $message .= "<br> Error might indicate successful injection!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 11 - UPDATE Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <style>
        .update-container {
            max-width: 700px;
            margin: 2rem auto;
            background: #1f2937;
            color: #e2e8f0;
            padding: 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 25px rgba(31, 41, 55, 0.4);
            border: 1px solid #10b981;
        }
        
        .user-profile {
            background: #111827;
            border: 2px solid #10b981;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #6ee7b7;
        }
        
        .form-group input, .form-group textarea {
            background: #111827;
            color: #e2e8f0;
            border: 2px solid #10b981;
        }
        
        .form-group input:focus, .form-group textarea:focus {
            border-color: #34d399;
            box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.2);
        }
        
        .form-group textarea {
            min-height: 80px;
            resize: vertical;
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
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
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }
        
        .update-info {
            background: #111827;
            border: 2px solid #10b981;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #6ee7b7;
        }
        
        .sql-structure {
            background: #111827;
            border: 2px solid #34d399;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            color: #a7f3d0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
        }
        
        body {
            background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> Level 11 - UPDATE Injection</h1>
            <p>Exploit UPDATE statement vulnerabilities for privilege escalation</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>
        
        <div class="update-container">
            <div class="update-info">
                <h4> UPDATE Injection Challenge</h4>
                <p>Manipulate the UPDATE query to escalate your privileges to admin!</p>
                <p><strong>Goal:</strong> Change your role from 'user' to 'admin'</p>
            </div>
            
            <?php if ($current_user): ?>
                <div class="user-profile">
                    <h4> Current Profile</h4>
                    <p><strong>ID:</strong> <?= htmlspecialchars($current_user['id']) ?></p>
                    <p><strong>Username:</strong> <?= htmlspecialchars($current_user['username']) ?></p>
                    <p><strong>Role:</strong> <?= htmlspecialchars($current_user['role']) ?></p>
                    <p><strong>Email:</strong> <?= htmlspecialchars($current_user['email'] ?? 'Not set') ?></p>
                </div>
            <?php endif; ?>
            
            <div class="sql-structure">
                <strong>UPDATE Query Structure:</strong><br>
                UPDATE users SET email = '$email', phone = '$phone', bio = '$bio', website = '$website' <br>
                WHERE id = <?= $_SESSION['user_id'] ?>
            </div>
            
            <?php if ($message): ?>
                <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                    <?= $message ?>
                </div>
            <?php endif; ?>
            
            <h3> Update Profile</h3>
            <form method="POST" class="login-form">
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="text" id="email" name="email" 
                           value="<?= htmlspecialchars($current_user['email'] ?? '') ?>" 
                           placeholder="Enter email address (vulnerable field!)" required>
                </div>
                
                <div class="form-group">
                    <label for="phone">Phone:</label>
                    <input type="text" id="phone" name="phone" 
                           value="<?= htmlspecialchars($current_user['phone'] ?? '') ?>" 
                           placeholder="Enter phone number">
                </div>
                
                <div class="form-group">
                    <label for="bio">Bio:</label>
                    <textarea id="bio" name="bio" 
                              placeholder="Enter bio description"><?= htmlspecialchars($current_user['bio'] ?? '') ?></textarea>
                </div>
                
                <div class="form-group">
                    <label for="website">Website:</label>
                    <input type="text" id="website" name="website" 
                           value="<?= htmlspecialchars($current_user['website'] ?? '') ?>" 
                           placeholder="Enter website URL">
                </div>
                
                <button type="submit" class="submit-btn">Update Profile</button>
            </form>
        </div>
        
        <?= render_hint_section(get_level_hints(11), 'Hints for Level 11'); ?>
        
        <div class="navigation">
            <a href="level10.php">&larr; Previous Level</a>
            <a href="level12.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>


