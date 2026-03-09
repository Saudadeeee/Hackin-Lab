<?php
// Level 3: Stacked Query Login - Multiple SQL Statements
// Goal: Use stacked queries to modify data and login as admin

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(3);

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

    // Only check if user exists first, then allow stacked queries for manipulation
    $check_sql = "SELECT COUNT(*) as count FROM users WHERE username = '$username'";
    $check_result = $conn->query($check_sql);
    $user_exists = $check_result && $check_result->fetch_assoc()['count'] > 0;

    if (!$user_exists) {
        $message = "User does not exist. Try creating an admin account first.";
    } else {
        // Vulnerable to stacked queries - allows multiple statements
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        try {
            // Enable multi_query to allow stacked queries
            if ($conn->multi_query($sql)) {
                do {
                    if ($result = $conn->store_result()) {
                            if ($result->num_rows > 0) {
                                $user_data = $result->fetch_assoc();
                                if ($user_data['role'] === 'admin') {
                                    $success = true;
                                $flag = get_flag_for_level(3);
                                $message = "Great job! You executed stacked queries to gain admin access.<br>";
                                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                                $message .= "Admin User: " . htmlspecialchars($user_data['username']);
                            } else {
                                $message = "Login successful as: " . htmlspecialchars($user_data['username']) . " (" . htmlspecialchars($user_data['role']) . ")";
                            }
                        }
                        $result->free();
                    }
                } while ($conn->next_result());

                if (!$success && !$message) {
                    $message = "Login failed: Invalid password. Try modifying the user's role or password first.";
                }
            }
        } catch (Exception $e) {
            $message = "Database error: " . $e->getMessage();
            $message .= "<br><br>SQL Query: " . htmlspecialchars($sql);
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 - Stacked Query Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 3 - Stacked Query Login</h1>
            <p>Execute multiple SQL statements in a single injection attack.</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-comment">// Vulnerable to stacked queries - allows multiple statements</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"SELECT * FROM users WHERE username = '<span class="php-variable">$username</span>' AND password = '<span class="php-variable">$password</span>'"</span>;</span>
<span class="php-keyword">try</span> {
    <span class="php-comment">// Enable multi_query to allow stacked queries</span>
    <span class="php-keyword">if</span> (<span class="php-variable">$conn</span>-&gt;<span class="php-function">multi_query</span>(<span class="php-variable">$sql</span>)) {
        <span class="php-keyword">do</span> {
            <span class="php-keyword">if</span> (<span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">store_result</span>()) {
                <span class="php-keyword">if</span> (<span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
                    <span class="php-variable">$user_data</span> = <span class="php-variable">$result</span>-&gt;<span class="php-function">fetch_assoc</span>();
                    <span class="php-keyword">if</span> (<span class="php-variable">$user_data</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
                        <span class="php-comment">// success — return flag</span>
                    }
                }
                <span class="php-variable">$result</span>-&gt;<span class="php-function">free</span>();
            }
        } <span class="php-keyword">while</span> (<span class="php-variable">$conn</span>-&gt;<span class="php-function">next_result</span>());
    }
} <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
    <span class="php-variable">$message</span> = <span class="php-string">"Database error: "</span> . <span class="php-variable">$e</span>-&gt;<span class="php-function">getMessage</span>();
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$conn-&gt;multi_query()</code> processes the entire input as a batch of semicolon-separated statements. Appending <code>; UPDATE users SET role='admin'...</code> to the injection point executes a second, attacker-controlled statement in the same call.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Industrial Control Login<br>
                        <strong>Objective:</strong> Use stacked queries to modify the database and gain admin access.
                        The system allows multiple SQL statements — you can INSERT, UPDATE, or CREATE new admin accounts.
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

        <?= render_hint_section(get_level_hints(3), 'Hints for Level 3'); ?>

    <?= render_inline_flag_form(3, $_flag_result) ?>

        <div class="navigation">
            <a href="level2.php">&larr; Previous Level</a>
            <a href="level4.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
