<?php
// Level 6: Time-Based Blind Login - Use time delays to extract information
// Goal: Login as admin using time-based blind injection

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(6);

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
$time_taken = 0;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $start_time = microtime(true);

    // Time-based blind injection - uses SLEEP() function
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND role = 'admin'";

    try {
        $result = $conn->query($sql);
        $time_taken = round((microtime(true) - $start_time) * 1000, 2); // milliseconds

        if ($result && $result->num_rows > 0) {
            $admin_data = $result->fetch_assoc();
            $success = true;
            $flag = get_flag_for_level(6);
            $message = "Great job! You used time-based injection to log in as admin.<br>";
            $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
            $message .= "Query execution time: {$time_taken}ms<br>";
            $message .= "Welcome, " . htmlspecialchars($admin_data['username']) . "!";
        } else {
            $message = "Login failed: Invalid credentials.<br>";
            $message .= "Query execution time: {$time_taken}ms";
        }
    } catch (Exception $e) {
        $time_taken = round((microtime(true) - $start_time) * 1000, 2);
        $message = "Login failed: Invalid credentials.<br>";
        $message .= "Query execution time: {$time_taken}ms";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 6 - Time-Based Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 6 - Time-Based Login</h1>
            <p>Use time delays to extract information and log in as admin.</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-keyword">if</span> (<span class="php-variable">$_POST</span>) {
    <span class="php-variable">$username</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$password</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$start_time</span> = <span class="php-function">microtime</span>(<span class="php-string">true</span>);

    <span class="php-comment">// Time-based blind injection - uses SLEEP() function</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>' AND role = 'admin'"</span>;</span>
    <span class="php-keyword">try</span> {
        <span class="php-variable">$result</span>     = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
        <span class="php-variable">$time_taken</span> = <span class="php-function">round</span>((<span class="php-function">microtime</span>(<span class="php-string">true</span>) - <span class="php-variable">$start_time</span>) * 1000, 2);

        <span class="php-keyword">if</span> (<span class="php-variable">$result</span> &amp;&amp; <span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
            <span class="php-comment">// success — return flag + execution time</span>
        } <span class="php-keyword">else</span> {
            <span class="php-variable">$message</span> = <span class="php-string">"Login failed. Query time: {$time_taken}ms"</span>;
        }
    } <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
        <span class="php-variable">$time_taken</span> = <span class="php-function">round</span>((<span class="php-function">microtime</span>(<span class="php-string">true</span>) - <span class="php-variable">$start_time</span>) * 1000, 2);
        <span class="php-variable">$message</span>    = <span class="php-string">"Login failed. Query time: {$time_taken}ms"</span>;
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> is concatenated without sanitisation. Injecting <code>' AND SLEEP(5)-- -</code> causes a measurable delay when the condition is true, leaking boolean information through response timing. The server echoes <code>$time_taken</code> as a built-in oracle.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Temporal Security System<br>
                        <strong>Objective:</strong> Use time-based blind injection to extract admin credentials.
                        Monitor response times carefully — <code>SLEEP()</code> delays are your only signal.
                        The server reports query execution time in milliseconds after every request.
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

        <?= render_hint_section(get_level_hints(6), 'Hints for Level 6'); ?>

    <?= render_inline_flag_form(6, $_flag_result) ?>

        <div class="navigation">
            <a href="level5.php">&larr; Previous Level</a>
            <a href="level7.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
