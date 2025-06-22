<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$name = $_POST['name'] ?? '';
$email = $_POST['email'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $name) {
    $sql = "INSERT INTO users (username) VALUES ('$name')";
    if ($mysqli->query($sql)) {
        echo 'User registered successfully';
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
    <title>Level 10 - INSERT-based SQL Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Level 10 - INSERT-based SQL Injection</h1>
            <p><strong>Attack Type:</strong> Exploit INSERT statements to manipulate database structure and extract sensitive data</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">INSERT INTO users (username) VALUES ('<?php echo htmlspecialchars($_POST['name'] ?? 'NULL'); ?>')</div>
            
            <?php
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['name'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $name = $_POST['name'];
                $email = $_POST['email'] ?? '';

                if ($name) {
                    $sql = "INSERT INTO users (username) VALUES ('$name')";
                    if ($mysqli->query($sql)) {
                        echo '✅ User registered successfully';
                        echo '<br>Last inserted ID: ' . $mysqli->insert_id;
                        
                        // Show the inserted data to demonstrate the injection
                        $checkSql = "SELECT username FROM users WHERE id = " . $mysqli->insert_id;
                        $result = $mysqli->query($checkSql);
                        if ($result && $result->num_rows > 0) {
                            echo '<br><strong>Inserted username:</strong> ';
                            while ($row = $result->fetch_row()) {
                                echo htmlspecialchars($row[0]) . '<br>';
                            }
                        }
                        
                        // Also check for any new users that might contain flags
                        $flagCheck = "SELECT username FROM users WHERE username LIKE '%FLAG%' ORDER BY id DESC LIMIT 5";
                        $flagResult = $mysqli->query($flagCheck);
                        if ($flagResult && $flagResult->num_rows > 0) {
                            echo '<br><strong>🏆 Potential flags found:</strong><br>';
                            while ($row = $flagResult->fetch_row()) {
                                echo '• ' . htmlspecialchars($row[0]) . '<br>';
                            }
                        }
                    } else {
                        echo '<div class="error">❌ Error: '.$mysqli->error.'</div>';
                    }
                } else {
                    echo '<div class="error">❌ Please provide a name</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 User Registration Form:</h3>
            <form method="post">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($_POST['name'] ?? ''); ?>" placeholder="Enter your name">
                </div>
                <div class="form-group">
                    <label for="email">Email (optional for demo):</label>
                    <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" placeholder="Enter your email">
                </div>
                <button type="submit" class="btn">🚀 Register User</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding INSERT Injection</h4>
                    <p>INSERT statements can also be vulnerable to SQL injection when user input is directly concatenated.</p>
                    <p>Try entering a simple name like: <code>alice</code></p>
                    <p>Notice how it gets inserted into the VALUES clause.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking the INSERT Syntax</h4>
                    <p>We can break out of the VALUES clause and add our own SQL.</p>
                    <p>Try: <code>alice'), ('bob</code></p>
                    <p>This will insert two users instead of one.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Adding Subqueries</h4>
                    <p>We can use subqueries within INSERT statements to extract data.</p>
                    <p>Try: <code>alice'), ((SELECT flag FROM levels WHERE id=10))</code></p>
                    <p>This attempts to insert the flag as a username.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Multiple INSERT Technique</h4>
                    <p>Since we need to close the current INSERT and add our payload:</p>
                    <p>Try: <code>test'), ((SELECT CONCAT('FLAG_LEVEL_10:', flag) FROM levels WHERE id=10)), ('dummy</code></p>
                    <p>This inserts three records: 'test', the flag, and 'dummy'.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag for level 10 using INSERT injection:</p>
                    <p><code>exploit'), ((SELECT flag FROM levels WHERE id=10)), ('end</code></p>
                    <p>This payload will:</p>
                    <p>1. Insert 'exploit' as first user</p>
                    <p>2. Insert the flag as second user</p>
                    <p>3. Insert 'end' as third user</p>
                    <p>The flag will appear in the results showing inserted usernames!</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level9.php">⬅️ Previous Level</a>
            <a href="level11.php">➡️ Next Level</a>
            <a href="submit.php?level=10">🏆 Submit Flag</a>
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
            <h1>🎯 Level 10 - INSERT-based SQL Injection</h1>
            <p><strong>Attack Type:</strong> Exploit INSERT statements to manipulate database structure and extract sensitive data</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">INSERT INTO users (username) VALUES ('<?php echo htmlspecialchars($_POST['name'] ?? 'NULL'); ?>')</div>
            
            <?php
            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['name'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $name = $_POST['name'];
                $email = $_POST['email'] ?? '';

                if ($name && $email) {
                    $sql = "INSERT INTO users (username) VALUES ('$name')";
                    if ($mysqli->query($sql)) {
                        echo '✅ User registered successfully';
                    } else {
                        echo '<div class="error">❌ Error: '.$mysqli->error.'</div>';
                    }
                } else {
                    echo '<div class="error">❌ Please fill in all fields</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 User Registration Form:</h3>
            <form method="post">
                <div class="form-group">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($_POST['name'] ?? ''); ?>" placeholder="Enter your name">
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" placeholder="Enter your email">
                </div>
                <button type="submit" class="btn">🚀 Register User</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding INSERT Injection</h4>
                    <p>INSERT statements can also be vulnerable to SQL injection when user input is directly concatenated.</p>
                    <p>Try entering a simple name like: <code>alice</code></p>
                    <p>Notice how it gets inserted into the VALUES clause.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking the INSERT Syntax</h4>
                    <p>We can break out of the VALUES clause and add our own SQL.</p>
                    <p>Try: <code>alice'), ('bob</code></p>
                    <p>This will insert two users instead of one.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Adding Subqueries</h4>
                    <p>We can use subqueries within INSERT statements to extract data.</p>
                    <p>Try: <code>alice'), ((SELECT flag FROM levels WHERE id=10))</code></p>
                    <p>This attempts to insert the flag as a username.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Error-based Data Extraction</h4>
                    <p>If direct insertion doesn't work, we can use error-based techniques.</p>
                    <p>Try: <code>alice') AND (SELECT flag FROM levels WHERE id=10)='</code></p>
                    <p>This will cause an error that might reveal the flag.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the flag for level 10 using INSERT injection:</p>
                    <p><code>test'), ((SELECT CONCAT('FLAG:', flag) FROM levels WHERE id=10)), ('dummy</code></p>
                    <p>This payload inserts the flag as a new user record.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level9.php">⬅️ Previous Level</a>
            <a href="level11.php">➡️ Next Level</a>
            <a href="submit.php?level=10">🏆 Submit Flag</a>
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
