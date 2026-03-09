<?php
// Level 13: Comment Bypass - Advanced Comment Filtering
// Goal: Bypass comment-based filtering to achieve admin access

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(13);
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
$blocked_patterns = [];

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Advanced comment filtering
    $dangerous_patterns = [
        '--',      // SQL line comments
        '#',       // MySQL hash comments
        '/*',      // Block comment start
        '*/',      // Block comment end
        ';',       // Statement separator
    ];

    $input_blocked = false;
    foreach ($dangerous_patterns as $pattern) {
        if (stripos($username, $pattern) !== false || stripos($password, $pattern) !== false) {
            $blocked_patterns[] = $pattern;
            $input_blocked = true;
        }
    }

    if ($input_blocked) {
        $message = "Security filter triggered!<br>";
        $message .= "Blocked patterns detected: " . implode(', ', array_unique($blocked_patterns)) . "<br>";
        $message .= "Advanced comment filtering is active.";
    } else {
        // VULNERABLE query (if filters are bypassed)
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        try {
            $result = $conn->query($sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(13);
                    $message = "Great job! You bypassed the comment filters and gained admin access.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "Bypassed patterns: " . implode(', ', $dangerous_patterns) . "<br>";
                    $message .= "SQL query: <code>" . htmlspecialchars($sql) . "</code><br>";
                    $message .= "Administrator access granted!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                    $message .= "<br>You still need the admin role to claim the flag.";
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
    <title>Level 13 - Comment Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 13 - Comment Bypass</h1>
            <p>Bypass advanced comment filtering to achieve admin access</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Blocked: --, #, /*, */, ;</span>
<span class="php-variable">$input_blocked</span> = <span class="php-keyword">false</span>;
<span class="php-keyword">foreach</span> (<span class="php-variable">$dangerous_patterns</span> <span class="php-keyword">as</span> <span class="php-variable">$pattern</span>) {
    <span class="php-keyword">if</span> (<span class="php-function">stripos</span>(<span class="php-variable">$username</span>, <span class="php-variable">$pattern</span>) !== <span class="php-keyword">false</span>
     || <span class="php-function">stripos</span>(<span class="php-variable">$password</span>,  <span class="php-variable">$pattern</span>) !== <span class="php-keyword">false</span>)
        <span class="php-variable">$input_blocked</span> = <span class="php-keyword">true</span>;
}

<span class="php-keyword">if</span> (!<span class="php-variable">$input_blocked</span>) {
    <span class="php-comment">// VULNERABLE: raw SQL from unescaped input</span>
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
                    <strong>Vulnerability:</strong>&nbsp; The filter only rejects specific comment tokens (<code>--</code>, <code>#</code>, <code>/*</code>, <code>*/</code>, <code>;</code>). The SQL itself is still raw string concatenation. Any injection payload that avoids those exact tokens — such as using <code>'OR'1'='1</code> without a trailing comment — can still manipulate the query.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This login form actively filters common SQL comment sequences. However, the underlying SQL query is still built from raw string concatenation.</p>
                    <p><strong>Goal:</strong> Bypass the comment filter and login as <code>admin</code> to capture the flag!</p>

                    <div class="security-filters">
                        <h4>Active Security Filters</h4>
                        <p>The following patterns are blocked:</p>
                        <span class="blocked-pattern">--</span>
                        <span class="blocked-pattern">#</span>
                        <span class="blocked-pattern">/*</span>
                        <span class="blocked-pattern">*/</span>
                        <span class="blocked-pattern">;</span>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Secure Login</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="submit-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(13), 'Hints for Level 13'); ?>

    <?= render_inline_flag_form(13, $_flag_result) ?>

        <div class="navigation">
            <a href="level12.php">&larr; Previous Level</a>
            <a href="level14.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
