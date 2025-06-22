<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$query = $_GET['query'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Sandbox</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 SQL Sandbox</h1>
            <p>Practice SQL queries in a safe environment</p>
        </div>

        <div class="form-container">
            <form method="get">
                <div class="form-group">
                    <label for="query">SQL Query:</label>
                    <input type="text" id="query" name="query" 
                           placeholder="e.g., SELECT * FROM users LIMIT 5" 
                           value="<?php echo htmlspecialchars($_GET['query'] ?? ''); ?>">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <?php
            $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
            $query = $_GET['query'] ?? '';
            
            if ($query) {
                echo '<h3>Query Preview:</h3>';
                echo '<div class="code-block">' . htmlspecialchars($query) . '</div>';
                
                $start = microtime(true);
                $result = $mysqli->query($query);
                $delta = microtime(true) - $start;
                
                if (!$result) {
                    echo '<div class="error">❌ Error: ' . $mysqli->error . '</div>';
                } else {
                    echo '<div class="result">';
                    echo '<p><strong>✅ Query executed successfully!</strong></p>';
                    echo '<p>⏱️ Execution time: ' . number_format($delta, 4) . ' seconds</p>';
                    
                    if ($result === true) {
                        echo '<p>Rows affected: ' . $mysqli->affected_rows . '</p>';
                    } else {
                        echo '<p>Rows returned: ' . $result->num_rows . '</p>';
                        $result->free();
                    }
                    echo '</div>';
                }
            }
            ?>
            
            <div class="info-box">
                <h4>📚 Available Tables:</h4>
                <ul>
                    <li><strong>users</strong> - id, username, password</li>
                    <li><strong>levels</strong> - id, flag</li>
                    <li><strong>meta</strong> - id, mkey, mvalue</li>
                </ul>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="submit.php?level=1">🏆 Submit Flags</a>
        </div>
    </div>
</body>
</html>