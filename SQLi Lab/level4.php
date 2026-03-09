<?php
// Level 4: Basic WAF Bypass - Multiple Security Layers
// Goal: Bypass multiple security measures to login as admin

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(4);

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
$show_hint = false;

// Simple anti-automation
session_start();
if (!isset($_SESSION['attempts'])) {
    $_SESSION['attempts'] = 0;
}

if ($_POST) {
    $_SESSION['attempts']++;

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Advanced WAF simulation - multiple filters
    $blocked_words = ['union', 'select', 'or', 'and', 'admin', '--', '#', '/*', '*/', 'drop', 'insert', 'update', 'delete'];
    $username_lower = strtolower($username);
    $password_lower = strtolower($password);

    // Check for blocked words
    foreach ($blocked_words as $word) {
        if (strpos($username_lower, $word) !== false || strpos($password_lower, $word) !== false) {
            $message = "WAF blocked: Suspicious pattern detected: '$word'";
            break;
        }
    }

    if (!$message) {
        // Remove quotes and some special chars (but can be bypassed)
        $username = str_replace(["'", '"', ';'], "", $username);
        $password = str_replace(["'", '"', ';'], "", $password);

        // Query with role check
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";

        try {
            $result = $conn->query($sql);
            if ($result && $result->num_rows > 0) {
                $admin_data = $result->fetch_assoc();
                $success = true;
                $flag = get_flag_for_level(4);
                $message = "Great job! You bypassed the filters and logged in as admin.<br>";
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                $message .= "Welcome, " . htmlspecialchars($admin_data['username']) . "!<br>";
                $message .= "Keep exploring different filter evasion techniques.";
            } else {
                $message = "Authentication failed. Invalid credentials.";
            }
        } catch (Exception $e) {
            $message = "Authentication failed. Security violation detected.";
        }
    }

    // Show progressive hints based on attempts
    if ($_SESSION['attempts'] > 3 && !$success) {
        $show_hint = true;
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 4 - Basic WAF Bypass | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 4 - Basic WAF Bypass</h1>
            <p>The ultimate SQL injection challenge with multiple security layers</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Blocked keywords list</span>
<span class="php-variable">$blocked_words</span> = [<span class="php-string">'union'</span>, <span class="php-string">'select'</span>, <span class="php-string">'or'</span>, <span class="php-string">'and'</span>,
                   <span class="php-string">'admin'</span>, <span class="php-string">'--'</span>, <span class="php-string">'#'</span>, <span class="php-string">'/*'</span>, <span class="php-string">'*/'</span>, ...];
<span class="php-keyword">foreach</span> (<span class="php-variable">$blocked_words</span> <span class="php-keyword">as</span> <span class="php-variable">$word</span>) {
    <span class="php-keyword">if</span> (<span class="php-function">strpos</span>(<span class="php-variable">$username_lower</span>, <span class="php-variable">$word</span>) !== <span class="php-string">false</span>) {
        <span class="php-variable">$message</span> = <span class="php-string">"WAF blocked: pattern detected"</span>;
    }
}

<span class="php-keyword">if</span> (!<span class="php-variable">$message</span>) {
    <span class="php-comment">// Remove quotes and some special chars (but can be bypassed)</span>
    <span class="php-variable">$username</span> = <span class="php-function">str_replace</span>([<span class="php-string">"'"</span>, <span class="php-string">'"'</span>, <span class="php-string">';'</span>], <span class="php-string">""</span>, <span class="php-variable">$username</span>);
    <span class="php-variable">$password</span> = <span class="php-function">str_replace</span>([<span class="php-string">"'"</span>, <span class="php-string">'"'</span>, <span class="php-string">';'</span>], <span class="php-string">""</span>, <span class="php-variable">$password</span>);

    <span class="php-comment">// Query with role check</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>' AND role = 'admin'"</span>;</span>
    <span class="php-keyword">try</span> {
        <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
        <span class="php-keyword">if</span> (<span class="php-variable">$result</span> &amp;&amp; <span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
            <span class="php-comment">// success — return flag</span>
        }
    } <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
        <span class="php-variable">$message</span> = <span class="php-string">"Authentication failed."</span>;
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; The WAF blocks exact keyword matches (case-sensitive normalised), strips <code>'</code>, <code>"</code>, and <code>;</code> — but the final query still concatenates unsanitised input. Mixed-case variants like <code>aNd</code> or encoding tricks slip past the blocklist.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> CyberCorp — Administrator Access Portal<br>
                        <strong>Objective:</strong> Bypass all WAF rules and log in as admin.<br>
                        <strong>WAF Rules Active:</strong> keyword blocklist (union, select, or, and, admin, --, #),
                        quote stripping, semicolon removal.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : ($show_hint ? 'info' : 'error') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Administrator ID</label>
                            <input type="text" id="username" name="username" placeholder="Enter administrator username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Security Key</label>
                            <input type="password" id="password" name="password" placeholder="Enter security passphrase" required>
                        </div>

                        <button type="submit" class="login-btn">Authenticate</button>
                    </form>

                    <p style="font-size:0.75rem; color:var(--text-faint); margin-top:0.5rem;">
                        <?= $_SESSION['attempts'] ?> authentication attempt(s) this session
                    </p>
                </div>
            </div>
        </div>

        <?php if ($show_hint): ?>
            <?= render_hint_section(get_level_hints(4), 'WAF Bypass Techniques'); ?>
        <?php endif; ?>

    <?= render_inline_flag_form(4, $_flag_result) ?>

        <div class="navigation">
            <a href="level3.php">&larr; Previous Level</a>
            <a href="level5.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
