<?php
// Level 8: Registration + Login System - Second Order Injection
// Goal: Register with malicious payload, then trigger it during login

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(8);
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
$mode = $_GET['mode'] ?? 'login';

// Registration process
if ($_POST && $mode === 'register') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $email = $_POST['email'] ?? '';

    // Vulnerable registration - stores user input directly
    $sql = "INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email')";

    try {
        if ($conn->query($sql)) {
            $message = " Registration successful! You can now login with your credentials.";
        } else {
            $message = " Registration failed: " . $conn->error;
        }
    } catch (Exception $e) {
        $message = " Registration failed: " . $e->getMessage();
    }
}

// Login process - triggers second order injection
if ($_POST && $mode === 'login') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // First query - retrieves user data (including malicious stored data)
    $sql1 = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result1 = $conn->query($sql1);

    if ($result1 && $result1->num_rows > 0) {
        $user_data = $result1->fetch_assoc();

        // Second query - uses stored user data (VULNERABLE!)
        $stored_email = $user_data['email'];
        $sql2 = "SELECT COUNT(*) as count FROM users WHERE email = '$stored_email' AND role = 'admin'";

        try {
            $result2 = $conn->query($sql2);
            if ($result2) {
                $admin_check = $result2->fetch_assoc();
                if ($admin_check['count'] > 0 || $user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(8);
                    $message = "Great job! You exploited a second-order injection to become admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "Your payload was stored during registration and executed during login.<br>";
                    $message .= "Welcome, " . htmlspecialchars($user_data['username']) . "!";
                } else {
                    $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role'] ?? 'user') . ")";
                }
            }
        } catch (Exception $e) {
            $message = "Second query error: " . $e->getMessage();
            $message .= "<br>Your stored payload triggered an error - injection successful!";
        }
    } else {
        $message = "Login failed: Invalid credentials";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 - Registration System | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 8 - Registration System</h1>
            <p>Exploit second-order injection through registration and login process</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Step 1 — Registration: payload stored verbatim</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"INSERT INTO users (username, password, email) VALUES ('<span class="php-variable">$username</span>', '<span class="php-variable">$password</span>', '<span class="php-variable">$email</span>')"</span>;</span>
<span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);

<span class="php-comment">// Step 2 — Login: retrieves user, then reuses stored data</span>
<span class="php-variable">$sql1</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>'"</span>;
<span class="php-variable">$result1</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql1</span>);

<span class="php-keyword">if</span> (<span class="php-variable">$result1</span> &amp;&amp; <span class="php-variable">$result1</span>-&gt;num_rows &gt; 0) {
    <span class="php-variable">$user_data</span>    = <span class="php-variable">$result1</span>-&gt;<span class="php-function">fetch_assoc</span>();

    <span class="php-comment">// Second query - uses stored user data (VULNERABLE!)</span>
    <span class="php-variable">$stored_email</span> = <span class="php-variable">$user_data</span>[<span class="php-string">'email'</span>];
<span class="vuln-line">    <span class="php-variable">$sql2</span> = <span class="php-string">"SELECT COUNT(*) as count FROM users WHERE email = '<span class="php-variable">$stored_email</span>' AND role = 'admin'"</span>;</span>
    <span class="php-variable">$result2</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql2</span>);

    <span class="php-keyword">if</span> (<span class="php-variable">$result2</span>) {
        <span class="php-variable">$admin_check</span> = <span class="php-variable">$result2</span>-&gt;<span class="php-function">fetch_assoc</span>();
        <span class="php-keyword">if</span> (<span class="php-variable">$admin_check</span>[<span class="php-string">'count'</span>] &gt; 0 || <span class="php-variable">$user_data</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
            <span class="php-comment">// success — return flag</span>
        }
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; The registration form stores <code>$email</code> verbatim into the database. When the same user logs in later, the stored email value is pulled back out and concatenated directly into <code>$sql2</code> — a classic <em>second-order</em> (stored) injection. Register with <code>' OR '1'='1</code> as the email, then log in to trigger it.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Second-Order Injection Challenge<br>
                        <strong>Objective:</strong> Register with a malicious payload in the email field,
                        then trigger it during login. The payload is stored safely at registration time
                        but executed unsanitised when it is reused in the second query at login.
                    </div>

                    <div class="tab-switcher">
                        <a href="?mode=register" class="tab <?= $mode === 'register' ? 'active' : '' ?>">Register</a>
                        <a href="?mode=login" class="tab <?= $mode === 'login' ? 'active' : '' ?>">Login</a>
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <?php if ($mode === 'register'): ?>
                        <h3>Create Account</h3>
                        <form method="POST" class="login-form">
                            <div class="form-group">
                                <label for="username">Username:</label>
                                <input type="text" id="username" name="username" placeholder="Enter username" required>
                            </div>

                            <div class="form-group">
                                <label for="password">Password:</label>
                                <input type="password" id="password" name="password" placeholder="Enter password" required>
                            </div>

                            <div class="form-group">
                                <label for="email">Email:</label>
                                <input type="text" id="email" name="email" placeholder="Enter email (vulnerable field!)" required>
                            </div>

                            <button type="submit" class="submit-btn">Register</button>
                        </form>
                    <?php else: ?>
                        <h3>Login</h3>
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
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(8), 'Hints for Level 8'); ?>

    <?= render_inline_flag_form(8, $_flag_result) ?>

        <div class="navigation">
            <a href="level7.php">&larr; Previous Level</a>
            <a href="level9.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
