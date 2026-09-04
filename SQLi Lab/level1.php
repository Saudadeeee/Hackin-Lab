<?php
// Level 1: Basic Login Form - Authentication Bypass
// The database error is echoed back, which is how you map the query.
// Goal: Login as admin using SQL injection

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/teaching.php';
$_flag_result = handle_inline_flag_submit(1);

mysqli_report(MYSQLI_REPORT_OFF);

$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp';
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
}

$message = '';
$success = false;

if ($_POST) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Vulnerable SQL query - directly concatenates user input
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    $result = $conn->query($sql);

    // mysqli reporting is off, so a failed query returns false rather than
    // throwing. Surface the error: reading it is how you learn the query shape.
    if ($result === false) {
        $message = "Database error: " . htmlspecialchars($conn->error);
        $message .= "<br><br>SQL Query: " . htmlspecialchars($sql);
    } else {
        if ($result->num_rows > 0) {
            $userData = $result->fetch_assoc();
            if (($userData['role'] ?? '') === 'admin') {
                $success = true;
                $flag = get_flag_for_level(1);
                $message = "Great job! You successfully logged in as admin.<br>";
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                $message .= "Username: " . htmlspecialchars($userData['username']) . "<br>";
                $message .= "Role: " . htmlspecialchars($userData['role']);
            } else {
                $message = "Login successful, but you still need the admin account.<br>";
                $message .= "Current user: " . htmlspecialchars($userData['username']) . " (" . htmlspecialchars($userData['role'] ?? 'user') . ")";
            }
        } else {
            $message = "Login failed: Invalid username or password.";
        }
    }
}


?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 1 - Basic Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 1 - Basic Login</h1>
            <p>Your first SQL injection challenge. The database error is echoed back to you, so a broken payload tells you the shape of the query.</p>
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

    <span class="php-comment">// Vulnerable SQL query - directly concatenates user input</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>'"</span>;</span>
    <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);

    <span class="php-comment">// A failed query returns false. The error text is handed straight</span>
    <span class="php-comment">// back to the client, along with the statement that produced it.</span>
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-variable">$result</span> === <span class="php-keyword">false</span>) {
        <span class="php-variable">$message</span> = <span class="php-string">"Database error: "</span> . <span class="php-variable">$conn</span>-&gt;error;
        <span class="php-variable">$message</span> .= <span class="php-string">"&lt;br&gt;SQL Query: "</span> . <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$sql</span>);
    }</span> <span class="php-keyword">elseif</span> (<span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
        <span class="php-variable">$userData</span> = <span class="php-variable">$result</span>-&gt;<span class="php-function">fetch_assoc</span>();
        <span class="php-keyword">if</span> ((<span class="php-variable">$userData</span>[<span class="php-string">'role'</span>] ?? <span class="php-string">''</span>) === <span class="php-string">'admin'</span>) {
            <span class="php-comment">// success — return flag</span>
        }
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> and <code>$password</code> are concatenated directly into the SQL string with no sanitisation, so a quote in either field ends the literal and the rest of your input is parsed as SQL. A second, smaller flaw compounds it: the driver's error text and the failing statement are both returned to the client, which hands you the query's shape for free.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Admin Login Portal<br>
                        <strong>Objective:</strong> Log in as the <code>admin</code> user by abusing SQL injection.
                        Error messages are reflected back — use them to map the query structure.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="login-btn">Login</button>
                    </form>
                </div>
            </div>
        </div>

    <?= sqli_teach(1, ['input' => $_POST['username'] ?? '', 'input2' => $_POST['password'] ?? '', 'sql' => $sql ?? '', 'error' => (isset($conn) && $conn instanceof mysqli && $conn->error !== '') ? $conn->error : '', 'rows' => (isset($result) && $result instanceof mysqli_result) ? $result->num_rows : null, 'solved' => !empty($success) || !empty($_flag_result['already_completed'])]) ?>

        <?= render_hint_section(get_level_hints(1), 'Hints for Level 1'); ?>

    <?= render_inline_flag_form(1, $_flag_result) ?>

        <div class="navigation">
            <a href="level2.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>
<?php $conn->close(); ?>
