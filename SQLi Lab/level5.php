<?php
// Level 5: Blind Login - Boolean Based Injection
// Goal: Extract admin credentials using blind injection techniques

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(5);

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

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // True blind injection - only boolean response, no data leakage
    $sql = "SELECT COUNT(*) as count FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";

    try {
        $result = $conn->query($sql);
        if ($result) {
            $count = $result->fetch_assoc()['count'];
            if ($count > 0) {
                $success = true;
                $message = "Great job! You cracked the blind injection and logged in as admin.<br>";
                $flag = get_flag_for_level(5);
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                $message .= "This required patience to extract answers from yes/no responses.";
            } else {
                $message = "Access denied.";
            }
        } else {
            $message = "Security system triggered. Try a different blind injection technique.";
        }
    } catch (Exception $e) {
        // No error details in blind injection
        $message = "Security system triggered. Try a different blind injection technique.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 5 - Blind Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> Level 5 - Blind Login</h1>
            <p>No error messages, no data leakage - pure blind injection challenge</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-keyword">if</span> (<span class="php-variable">$_POST</span>) {
    <span class="php-variable">$username</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$password</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;

    <span class="php-comment">// True blind injection - only boolean response, no data leakage</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT COUNT(*) as count FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>' AND role = 'admin'"</span>;</span>
    <span class="php-keyword">try</span> {
        <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
        <span class="php-keyword">if</span> (<span class="php-variable">$result</span>) {
            <span class="php-variable">$count</span> = <span class="php-variable">$result</span>-&gt;<span class="php-function">fetch_assoc</span>()[<span class="php-string">'count'</span>];
            <span class="php-keyword">if</span> (<span class="php-variable">$count</span> &gt; 0) {
                <span class="php-comment">// success — return flag</span>
            } <span class="php-keyword">else</span> {
                <span class="php-variable">$message</span> = <span class="php-string">"Access denied."</span>;
            }
        }
    } <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
        <span class="php-comment">// No error details — suppressed for blind mode</span>
        <span class="php-variable">$message</span> = <span class="php-string">"Security system triggered."</span>;
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> and <code>$password</code> are concatenated unsanitised into the query. No error or data is reflected back — the only observable signal is <em>access denied</em> vs <em>success</em>. Boolean conditions like <code>' OR '1'='1</code> manipulate the COUNT result to force a non-zero return.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Secure Government Portal — Maximum Security Mode<br>
                        <strong>Objective:</strong> Extract admin credentials using boolean-based blind injection.
                        This system provides <em>no</em> feedback about SQL errors or data — only
                        "Access denied" or a successful login.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="login-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(5), 'Hints for Level 5'); ?>

    <?= render_inline_flag_form(5, $_flag_result) ?>

        <div class="navigation">
            <a href="level4.php">&larr; Previous Level</a>
            <a href="level6.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
