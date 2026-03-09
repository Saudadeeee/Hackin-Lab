<?php
// Level 11: UPDATE Injection - Profile Update System
// Goal: Exploit UPDATE statement to escalate privileges to admin

session_start();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/helpers.php';
$_flag_result = handle_inline_flag_submit(11);
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
$current_user = null;

// Initialize session with default user if not set
if (!isset($_SESSION['user_id'])) {
    $_SESSION['user_id'] = 2; // guest user
}

// Get current user info
$user_sql = "SELECT * FROM users WHERE id = " . $_SESSION['user_id'];
$user_result = $conn->query($user_sql);
if ($user_result && $user_result->num_rows > 0) {
    $current_user = $user_result->fetch_assoc();
}

if ($_POST) {
    $email = $_POST['email'] ?? '';
    $phone = $_POST['phone'] ?? '';
    $bio = $_POST['bio'] ?? '';
    $website = $_POST['website'] ?? '';

    $user_id = $_SESSION['user_id'];

    // VULNERABLE UPDATE query - directly concatenating user input
    $sql = "UPDATE users SET email = '$email', phone = '$phone', bio = '$bio', website = '$website' WHERE id = $user_id";

    try {
        // Execute the UPDATE query
        if ($conn->query($sql)) {
            // Get updated user info
            $check_sql = "SELECT * FROM users WHERE id = $user_id";
            $result = $conn->query($check_sql);

            if ($result && $result->num_rows > 0) {
                $updated_user = $result->fetch_assoc();

                if ($updated_user['role'] === 'admin') {
                    $success = true;
                    $flag = get_flag_for_level(11);
                    $message = "Great job! You exploited UPDATE injection to escalate privileges.<br>";
                    $message .= "<strong>Flag:</strong> <code>" . htmlspecialchars($flag) . "</code><br>";
                    $message .= "User ID: " . $updated_user['id'] . "<br>";
                    $message .= "Username: " . htmlspecialchars($updated_user['username']) . "<br>";
                    $message .= "New role: " . htmlspecialchars($updated_user['role']) . "<br>";
                    $message .= "UPDATE query: <code>" . htmlspecialchars($sql) . "</code>";
                } else {
                    $message = "Profile updated successfully!<br>";
                    $message .= "Username: " . htmlspecialchars($updated_user['username']) . "<br>";
                    $message .= "Email: " . htmlspecialchars($updated_user['email']) . "<br>";
                    $message .= " Role: " . htmlspecialchars($updated_user['role']) . "<br>";
                    $message .= " You need to escalate to admin role to get the flag!";
                }

                $current_user = $updated_user; // Update display
            }
        } else {
            $message = " Profile update failed: " . $conn->error;
            $message .= "<br> UPDATE Query: <code>" . htmlspecialchars($sql) . "</code>";
        }

    } catch (Exception $e) {
        $message = " UPDATE Error: " . $e->getMessage();
        $message .= "<br> UPDATE Query: <code>" . htmlspecialchars($sql) . "</code>";
        $message .= "<br> Error might indicate successful injection!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 11 - UPDATE Injection | SQL Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1> Level 11 - UPDATE Injection</h1>
            <p>Exploit UPDATE statement vulnerabilities for privilege escalation</p>
            <a href="index.php" class="back-btn">&larr; Back to Labs</a>
        </div>

        <div class="challenge-layout">
            <!-- Left: Source Code Panel -->
            <div class="code-panel">
                <h3>Vulnerable Source Code</h3>
                <div class="source-code">
                    <pre><code><span class="php-variable">$email</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>]   ?? <span class="php-string">''</span>;
<span class="php-variable">$phone</span>   = <span class="php-variable">$_POST</span>[<span class="php-string">'phone'</span>]   ?? <span class="php-string">''</span>;
<span class="php-variable">$bio</span>     = <span class="php-variable">$_POST</span>[<span class="php-string">'bio'</span>]     ?? <span class="php-string">''</span>;
<span class="php-variable">$website</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'website'</span>] ?? <span class="php-string">''</span>;

<span class="php-variable">$user_id</span> = <span class="php-variable">$_SESSION</span>[<span class="php-string">'user_id'</span>];

<span class="php-comment">// VULNERABLE: user fields in SET clause</span>
<span class="vuln-line"><span class="php-variable">$sql</span> = <span class="php-string">"UPDATE users SET email='$email',"</span>
     . <span class="php-string">" phone='$phone', bio='$bio',"</span>
     . <span class="php-string">" website='$website'"</span>
     . <span class="php-string">" WHERE id=$user_id"</span>;</span>

<span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(<span class="php-variable">$sql</span>);
<span class="php-variable">$updated</span> = <span class="php-variable">$conn</span>-&gt;<span class="php-function">query</span>(
    <span class="php-string">"SELECT * FROM users WHERE id=$user_id"</span>
);
<span class="php-keyword">if</span> (<span class="php-variable">$updated</span>[<span class="php-string">'role'</span>] === <span class="php-string">'admin'</span>) {
    <span class="php-comment">// flag awarded</span>
}</code></pre>
                </div>
                <div class="vuln-annotation">
                    <strong>Vulnerability:</strong>&nbsp; All four profile fields are interpolated directly into the SET clause. An attacker can close any string value early and append an extra assignment such as <code>, role='admin'</code> before the WHERE clause, escalating their own privileges.
                </div>
            </div>

            <!-- Right: Challenge Panel -->
            <div class="challenge-panel">
                <h3>Challenge</h3>
                <div class="panel-body">
                    <p>You are logged in as a regular user. The profile update form passes your input directly into a SQL UPDATE statement.</p>
                    <p><strong>Goal:</strong> Change your <code>role</code> from <code>user</code> to <code>admin</code> to capture the flag!</p>

                    <?php if ($current_user): ?>
                        <div class="user-profile">
                            <h4> Current Profile</h4>
                            <p><strong>ID:</strong> <?= htmlspecialchars($current_user['id']) ?></p>
                            <p><strong>Username:</strong> <?= htmlspecialchars($current_user['username']) ?></p>
                            <p><strong>Role:</strong> <?= htmlspecialchars($current_user['role']) ?></p>
                            <p><strong>Email:</strong> <?= htmlspecialchars($current_user['email'] ?? 'Not set') ?></p>
                        </div>
                    <?php endif; ?>

                    <?php if ($message): ?>
                        <div class="message <?= $success ? 'success' : (stripos($message, 'error') !== false ? 'error' : 'info') ?>">
                            <?= $message ?>
                        </div>
                    <?php endif; ?>

                    <h3>Update Profile</h3>
                    <form method="POST" class="login-form">
                        <div class="form-group">
                            <label for="email">Email:</label>
                            <input type="text" id="email" name="email"
                                   value="<?= htmlspecialchars($current_user['email'] ?? '') ?>"
                                   placeholder="Enter email address (vulnerable field!)" required>
                        </div>

                        <div class="form-group">
                            <label for="phone">Phone:</label>
                            <input type="text" id="phone" name="phone"
                                   value="<?= htmlspecialchars($current_user['phone'] ?? '') ?>"
                                   placeholder="Enter phone number">
                        </div>

                        <div class="form-group">
                            <label for="bio">Bio:</label>
                            <textarea id="bio" name="bio"
                                      placeholder="Enter bio description"><?= htmlspecialchars($current_user['bio'] ?? '') ?></textarea>
                        </div>

                        <div class="form-group">
                            <label for="website">Website:</label>
                            <input type="text" id="website" name="website"
                                   value="<?= htmlspecialchars($current_user['website'] ?? '') ?>"
                                   placeholder="Enter website URL">
                        </div>

                        <button type="submit" class="submit-btn">Update Profile</button>
                    </form>
                </div>
            </div>
        </div>

        <?= render_hint_section(get_level_hints(11), 'Hints for Level 11'); ?>

    <?= render_inline_flag_form(11, $_flag_result) ?>

        <div class="navigation">
            <a href="level10.php">&larr; Previous Level</a>
            <a href="level12.php">Next Level &rarr;</a>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
