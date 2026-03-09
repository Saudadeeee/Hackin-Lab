<?php
// Level 2: Union Based Login Form - Extract Data via UNION
// Goal: Login as admin and extract sensitive data using UNION attacks

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(2);

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
$user_data = null;

if ($_POST) {
    $user_id = $_POST['user_id'] ?? '';
    $password = $_POST['password'] ?? '';

    // Integer-based injection - no quotes around user_id
    $sql = "SELECT id, username, role FROM users WHERE id = $user_id AND password = '$password'";

    try {
        $result = $conn->query($sql);

        if ($result && $result->num_rows > 0) {
            $user_data = $result->fetch_all(MYSQLI_ASSOC);

            // Check if admin was found
            $admin_found = false;
            foreach ($user_data as $user) {
                if ($user['role'] === 'admin' || $user['username'] === 'admin') {
                    $admin_found = true;
                    break;
                }
            }

            if ($admin_found) {
                $success = true;
                $flag = get_flag_for_level(2);
                $message = "Great job! You used UNION-based integer injection to recover the admin account.<br>";
                $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code>";
            } else {
                $message = "Data extracted, but no admin found. Try UNION SELECT to inject admin data.";
            }
        } else {
            $message = "Login failed: Invalid credentials.";
        }
    } catch (Exception $e) {
        $message = "Database error: " . $e->getMessage();
        $message .= "<br><br>SQL Query: " . htmlspecialchars($sql);
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 2 - Union Login | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 2 - Union Login</h1>
            <p>Use UNION SELECT to extract data from other tables and log in as admin.</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-keyword">if</span> (<span class="php-variable">$_POST</span>) {
    <span class="php-variable">$user_id</span>  = <span class="php-variable">$_POST</span>[<span class="php-string">'user_id'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$password</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'password'</span>] ?? <span class="php-string">''</span>;

    <span class="php-comment">// Integer-based injection - no quotes around user_id</span>
<span class="vuln-line">    <span class="php-variable">$sql</span> = <span class="php-string">"SELECT id, username, role FROM users WHERE id = <span class="php-variable">$user_id</span> AND password = '<span class="php-variable">$password</span>'"</span>;</span>
    <span class="php-keyword">try</span> {
        <span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);

        <span class="php-keyword">if</span> (<span class="php-variable">$result</span> &amp;&amp; <span class="php-variable">$result</span>-&gt;num_rows &gt; 0) {
            <span class="php-variable">$user_data</span> = <span class="php-variable">$result</span>-&gt;<span class="php-function">fetch_all</span>(MYSQLI_ASSOC);

            <span class="php-comment">// Check if admin was found in result set</span>
            <span class="php-keyword">foreach</span> (<span class="php-variable">$user_data</span> <span class="php-keyword">as</span> <span class="php-variable">$user</span>) {
                <span class="php-keyword">if</span> (<span class="php-variable">$user</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
                    <span class="php-comment">// success — return flag</span>
                }
            }
        }
    } <span class="php-keyword">catch</span> (Exception <span class="php-variable">$e</span>) {
        <span class="php-variable">$message</span> = <span class="php-string">"Database error: "</span> . <span class="php-variable">$e</span>-&gt;<span class="php-function">getMessage</span>();
        <span class="php-variable">$message</span> .= <span class="php-string">"&lt;br&gt;SQL Query: "</span> . <span class="php-function">htmlspecialchars</span>(<span class="php-variable">$sql</span>);
    }
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$user_id</code> is inserted into the query <em>without quotes</em>, making it a numeric injection point. A <code>UNION SELECT</code> appended here can inject arbitrary rows — including a fake admin record — into the result set.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <div class="scenario">
                        <strong>Scenario:</strong> Corporate Login System<br>
                        <strong>Objective:</strong> Use UNION injection to extract admin credentials and log in successfully.
                        The query selects <code>id, username, role</code> — match that column count in your UNION.
                    </div>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="user_id">User ID:</label>
                            <input type="text" id="user_id" name="user_id" placeholder="Enter user ID (number)" required>
                        </div>

                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>

                        <button type="submit" class="login-btn">Login</button>
                    </form>

                    <?php if ($user_data && count($user_data) > 0): ?>
                        <h3>Extracted Data:</h3>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Role</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($user_data as $user): ?>
                                    <tr>
                                        <td><?= htmlspecialchars($user['id'] ?? 'N/A') ?></td>
                                        <td><?= htmlspecialchars($user['username'] ?? 'N/A') ?></td>
                                        <td><?= htmlspecialchars($user['role'] ?? 'N/A') ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(2), 'Hints for Level 2'); ?>

    <?= render_inline_flag_form(2, $_flag_result) ?>

        <div class="navigation">
            <a href="level1.php">&larr; Previous Level</a>
            <a href="level3.php" class="next-link">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
