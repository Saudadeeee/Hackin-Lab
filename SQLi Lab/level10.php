<?php
// Level 10: INSERT Injection - User Registration
// Goal: Exploit INSERT statement to become admin during registration

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(10);
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
    $email = $_POST['email'] ?? '';
    $fullname = $_POST['fullname'] ?? '';
    $phone = $_POST['phone'] ?? '';

    // VULNERABLE INSERT query - directly concatenating user input
    $sql = "INSERT INTO users (username, password, email, role) VALUES ('$username', 'defaultpass', '$email', 'user')";

    try {
        // Execute the INSERT query
        if ($conn->query($sql)) {
            $user_id = $conn->insert_id;

            // Check if the newly created user is admin
            $check_sql = "SELECT * FROM users WHERE id = $user_id";
            $result = $conn->query($check_sql);

            if ($result && $result->num_rows > 0) {
                $user_data = $result->fetch_assoc();

                if ($user_data['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(10);
                    $message = "Great job! You exploited INSERT injection to become admin.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "User ID: " . $user_data['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($user_data['username']) . "<br>";
                    $message .= "Role: " . htmlspecialchars($user_data['role']) . "<br>";
                    $message .= "INSERT query: <code>" . htmlspecialchars($sql) . "</code>";
                } else {
                    $message = "User registered successfully!<br>";
                    $message .= "User ID: " . $user_data['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($user_data['username']) . "<br>";
                    $message .= "Role: " . htmlspecialchars($user_data['role']) . "<br>";
                    $message .= "You need to become admin to get the flag!";
                }
            }
        } else {
            $message = "Registration failed: " . $conn->error;
            $message .= "<br> INSERT Query: <code>" . htmlspecialchars($sql) . "</code>";
        }

    } catch (Exception $e) {
        $message = "INSERT Error: " . $e->getMessage();
        $message .= "<br> INSERT Query: <code>" . htmlspecialchars($sql) . "</code>";
        $message .= "<br> Error might indicate successful injection!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 10 - INSERT Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Level 10 - INSERT Injection</h1>
            <p>Exploit INSERT statement vulnerabilities during user registration</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$username</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$email</span>    = <span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>]    ?? <span class="php-string">''</span>;

<span class="php-comment">// VULNERABLE: user input in VALUES clause</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"INSERT INTO users"</span>
     . <span class="php-string">" (username, password, email, role)"</span>
     . <span class="php-string">" VALUES ('$username', 'defaultpass',"</span>
     . <span class="php-string">"         '$email', 'user')"</span>;</span>

<span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
<span class="php-variable">$user_id</span> = <span class="php-variable">$conn</span>-&gt;insert_id;

<span class="php-variable">$check</span> = <span class="php-string">"SELECT * FROM users WHERE id = $user_id"</span>;
<span class="php-variable">$result</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$check</span>);
<span class="php-keyword">if</span> (<span class="php-variable">$result</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
    <span class="php-comment">// flag awarded</span>
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; <code>$username</code> and <code>$email</code> are interpolated directly into the VALUES clause. An attacker can close the string early and inject additional column values — for example, overriding the hardcoded <code>'user'</code> role with <code>'admin'</code>.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>This registration form inserts your supplied values directly into the database. The <code>role</code> column is hardcoded to <code>'user'</code> — but can you manipulate the query to override it?</p>
                    <p><strong>Goal:</strong> Register a user whose <code>role</code> is <code>admin</code> to capture the flag!</p>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>User Registration</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" placeholder="Enter username (vulnerable field!)" required>
                        </div>

                        <div class="form-group">
                            <label for="email">Email:</label>
                            <input type="email" id="email" name="email" placeholder="Enter email address" required>
                        </div>

                        <div class="form-group">
                            <label for="fullname">Full Name:</label>
                            <input type="text" id="fullname" name="fullname" placeholder="Enter full name">
                        </div>

                        <div class="form-group">
                            <label for="phone">Phone:</label>
                            <input type="text" id="phone" name="phone" placeholder="Enter phone number">
                        </div>

                        <button type="submit" class="submit-btn">Register Account</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(10), 'Hints for Level 10'); ?>

    <?= render_inline_flag_form(10, $_flag_result) ?>

        <div class="navigation">
            <a href="level9.php">&larr; Previous Level</a>
            <a href="level11.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
