<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$filter = $_GET['filter'] ?? '{}';

$json = json_decode($filter, true);
if ($json && isset($json['username'])) {
    $username = $json['username'];
    $sql = "SELECT id, username, password FROM users WHERE username = '$username'";
    $result = $mysqli->query($sql);
    
    if (!$result) {
        die('Error: '.$mysqli->error);
    }
    
    $users = [];
    while ($row = $result->fetch_assoc()) {
        $users[] = $row;
    }
    echo json_encode($users);
} else {
    echo 'Invalid JSON filter';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 13 - JSON Injection</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Level 13 - JSON Injection</h1>
            <p><strong>Attack Type:</strong> Exploit JSON-based query construction vulnerabilities to bypass filters and extract data</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT id, username, password FROM users WHERE username = '<?php 
            $filter = $_GET['filter'] ?? '{}';
            $json = json_decode($filter, true);
            echo htmlspecialchars($json['username'] ?? 'NULL');
            ?>'</div>
            
            <?php
            if (isset($_GET['filter'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $filter = $_GET['filter'];

                $json = json_decode($filter, true);
                if ($json && isset($json['username'])) {
                    $username = $json['username'];
                    $sql = "SELECT id, username, password FROM users WHERE username = '$username'";
                    $result = $mysqli->query($sql);
                    
                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $users = [];
                        while ($row = $result->fetch_assoc()) {
                            $users[] = $row;
                        }
                        if (count($users) > 0) {
                            echo '<pre>' . json_encode($users, JSON_PRETTY_PRINT) . '</pre>';
                        } else {
                            echo 'No users found';
                        }
                    }
                } else {
                    echo '<div class="error">Invalid JSON filter</div>';
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Own JSON Filter:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="filter">JSON Filter:</label>
                    <textarea id="filter" name="filter" rows="4" placeholder='{"username":"alice"}' oninput="updateQuery()"><?php echo htmlspecialchars($_GET['filter'] ?? ''); ?></textarea>
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding JSON Processing</h4>
                    <p>The application parses JSON input and extracts the username field for the SQL query.</p>
                    <p>Try: <code>{"username":"alice"}</code> - This should return alice's user data.</p>
                    <p>Notice how the JSON value gets inserted directly into the SQL WHERE clause.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: SQL Injection in JSON Values</h4>
                    <p>Since the username value is inserted directly into SQL without sanitization, we can inject SQL.</p>
                    <p>Try: <code>{"username":"alice' OR '1'='1"}</code></p>
                    <p>This should return all users because the OR condition is always true.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using UNION in JSON Values</h4>
                    <p>We can use UNION SELECT to combine results from different tables.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT 1,2,'test'--"}</code></p>
                    <p>Note: The users table has 3 columns (id, username, password).</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Exploring Database Structure</h4>
                    <p>Find the correct table structure and target the levels table for the flag.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT id,flag,'password' FROM levels--"}</code></p>
                    <p>This attempts to get flags from the levels table.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the specific flag for level 13:</p>
                    <p><code>{"username":"alice' UNION SELECT id,flag,'password' FROM levels WHERE id=13--"}</code></p>
                    <p>This payload bypasses the JSON processing and extracts the flag for level 13.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level12.php">⬅️ Previous Level</a>
            <a href="submit.php?level=13">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('filter').value;
        const codeBlock = document.querySelector('.code-block');
        try {
            const json = JSON.parse(input || '{}');
            const username = json.username || 'NULL';
            codeBlock.innerHTML = "SELECT id, username, password FROM users WHERE username = '" + username + "'";
        } catch(e) {
            codeBlock.innerHTML = "SELECT id, username, password FROM users WHERE username = 'INVALID_JSON'";
        }
    }

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
        background: #fff3cd;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        animation: fadeIn 0.5s ease-in;
    }
    .hint-btn {
        margin-bottom: 10px;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
</body>
</html>
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Level 13 - JSON Injection</h1>
            <p><strong>Attack Type:</strong> Exploit JSON-based query construction vulnerabilities to bypass filters and extract data</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT id, username, password FROM users WHERE username = '<?php 
            $filter = $_GET['filter'] ?? '{}';
            $json = json_decode($filter, true);
            echo htmlspecialchars($json['username'] ?? 'NULL');
            ?>'</div>
            
            <?php
            if (isset($_GET['filter'])) {
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                $filter = $_GET['filter'];

                $json = json_decode($filter, true);
                if ($json && isset($json['username'])) {
                    $username = $json['username'];
                    $sql = "SELECT id, username, password FROM users WHERE username = '$username'";
                    $result = $mysqli->query($sql);
                    
                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $users = [];
                        while ($row = $result->fetch_assoc()) {
                            $users[] = $row;
                        }
                        if (count($users) > 0) {
                            echo '<pre>' . json_encode($users, JSON_PRETTY_PRINT) . '</pre>';
                        } else {
                            echo 'No users found';
                        }
                    }
                } else {
                    echo '<div class="error">Invalid JSON filter</div>';
                }
                echo '</div>';
            }
            ?>
            
            <!-- Form input for custom payload -->
            <h3>🔧 Try Your Own JSON Filter:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="filter">JSON Filter:</label>
                    <textarea id="filter" name="filter" rows="4" placeholder='{"username":"alice"}' oninput="updateQuery()"><?php echo htmlspecialchars($_GET['filter'] ?? ''); ?></textarea>
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding JSON Processing</h4>
                    <p>The application parses JSON input and extracts the username field for the SQL query.</p>
                    <p>Try: <code>{"username":"alice"}</code> - This should return alice's user data.</p>
                    <p>Notice how the JSON value gets inserted directly into the SQL WHERE clause.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: SQL Injection in JSON Values</h4>
                    <p>Since the username value is inserted directly into SQL without sanitization, we can inject SQL.</p>
                    <p>Try: <code>{"username":"alice' OR '1'='1"}</code></p>
                    <p>This should return all users because the OR condition is always true.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using UNION in JSON Values</h4>
                    <p>We can use UNION SELECT to combine results from different tables.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT 1,2,'test'--"}</code></p>
                    <p>Note: The users table has 3 columns (id, username, password).</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Exploring Database Structure</h4>
                    <p>Find the correct table structure and target the levels table for the flag.</p>
                    <p>Try: <code>{"username":"alice' UNION SELECT id,flag,'password' FROM levels--"}</code></p>
                    <p>This attempts to get flags from the levels table.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Extract the specific flag for level 13:</p>
                    <p><code>{"username":"alice' UNION SELECT id,flag,'password' FROM levels WHERE id=13-- "}</code></p>
                    <p>This payload bypasses the JSON processing and extracts the flag for level 13.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level12.php">⬅️ Previous Level</a>
            <a href="submit.php?level=13">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('filter').value;
        const codeBlock = document.querySelector('.code-block');
        try {
            const json = JSON.parse(input || '{}');
            const username = json.username || 'NULL';
            codeBlock.innerHTML = "SELECT id, username, password FROM users WHERE username = '" + username + "'";
        } catch(e) {
            codeBlock.innerHTML = "SELECT id, username, password FROM users WHERE username = 'INVALID_JSON'";
        }
    }

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
        background: #fff3cd;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        animation: fadeIn 0.5s ease-in;
    }
    .hint-btn {
        margin-bottom: 10px;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
</body>
</html>
