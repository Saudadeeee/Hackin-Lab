<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo '<h3>Current Query:</h3>';
    echo '<div class="code-block">SELECT * FROM users WHERE username = \'' . htmlspecialchars($username) . '\' AND password = \'' . htmlspecialchars($password) . '\'</div>';
    
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $mysqli->query($sql);
    
    if (!$result) {
        echo '<div class="error">Error: '.$mysqli->error.'</div>';
    } else {
        if ($result->num_rows > 0) {
            echo '<div class="result" style="background: #d4edda; border-left-color: #28a745;">';
            echo '<h2>🎉 Welcome Admin!</h2>';
            echo '<p><strong>FLAG{auth_bypass_success}</strong></p>';
            echo '</div>';
        } else {
            echo '<div class="error">❌ Invalid credentials</div>';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 9 - Authentication Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚪 Level 9 - Authentication Bypass</h1>
            <p><strong>Attack Type:</strong> Bypass login mechanisms using SQL injection to circumvent authentication</p>
        </div>

        <div class="form-container">
            <?php
            $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                echo '<h3>Current Query:</h3>';
                echo '<div class="code-block">SELECT * FROM users WHERE username = \'' . htmlspecialchars($username) . '\' AND password = \'' . htmlspecialchars($password) . '\'</div>';
                
                $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
                $result = $mysqli->query($sql);
                
                if (!$result) {
                    echo '<div class="error">Error: '.$mysqli->error.'</div>';
                } else {
                    if ($result->num_rows > 0) {
                        echo '<div class="result" style="background: #d4edda; border-left-color: #28a745;">';
                        echo '<h2>🎉 Welcome Admin!</h2>';
                        echo '<p><strong>FLAG{auth_bypass_success}</strong></p>';
                        echo '</div>';
                    } else {
                        echo '<div class="error">❌ Invalid credentials</div>';
                    }
                }
            }
            ?>

            <h3>Admin Login</h3>
            <form method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>">
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" value="<?php echo htmlspecialchars($password); ?>">
                </div>
                <button type="submit" class="btn">🔐 Login</button>
            </form>
            
            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Authentication Bypass</h4>
                    <p>Authentication bypass is when we trick the login system into letting us in without knowing the correct credentials.</p>
                    <p>The key is to manipulate the SQL query to always return true.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: SQL Logic Manipulation</h4>
                    <p>The query checks: username = 'input' AND password = 'input'</p>
                    <p>We need to make this condition always true using SQL logic operators.</p>
                    <p>Try using OR conditions to make the statement always true.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using OR Operator</h4>
                    <p>The OR operator returns true if either condition is true.</p>
                    <p>Try in the username field: <code>admin' OR '1'='1</code></p>
                    <p>This makes the condition always true regardless of the password.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Using SQL Comments</h4>
                    <p>We can use SQL comments to ignore the password check entirely.</p>
                    <p>Try: <code>admin' OR '1'='1'--</code> in the username field</p>
                    <p>The -- comments out the rest of the query, ignoring the password check.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload - Complete Bypass</h4>
                    <p>Here are the complete payloads for authentication bypass:</p>
                    <p>Username: <code>admin' OR '1'='1'--</code></p>
                    <p>Password: <code>anything</code> (will be ignored due to the comment)</p>
                    <p>Alternative: Username: <code>admin' OR 1=1#</code></p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level8.php?user=admin&pass=test">⬅️ Previous Level</a>
            <a href="level10.php">➡️ Next Level</a>
            <a href="submit.php?level=9">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function showNextHint() {
        if (currentHint < maxHints) {
            currentHint++;
            document.getElementById('hint-' + currentHint).style.display = 'block';
            
            if (currentHint >= maxHints) {
                document.querySelector('.hint-btn').style.display = 'none';
            }
        }
    }
    </script>

    <style>
    .hint-container {
        margin: 20px 0;
    }
    .hint-box {
        margin: 15px 0;
        padding: 15px;
        background: #f8f9fa;
        border-radius: 8px;
        border-left: 4px solid #6c757d;
    }
    .hint-btn {
        margin-bottom: 10px;
    }
    </style>
</body>
</html>
