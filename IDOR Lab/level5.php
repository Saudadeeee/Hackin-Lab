<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$current_user_id = 1; // Alice — simulated session
$updatedUser     = null;
$flagFound       = false;
$submitted       = false;
$updateMessage   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $submitted = true;
    $db        = get_db();

    // VULNERABLE: directly uses all POST data including 'role'!
    $username = $_POST['username'] ?? '';
    $email    = $_POST['email']    ?? '';
    $role     = $_POST['role']     ?? 'user'; // Accepts role from POST!

    $stmt = $db->prepare("UPDATE users SET username=?, email=?, role=? WHERE id=?");
    $stmt->execute([$username, $email, $role, $current_user_id]);

    // Fetch updated user to show result
    $stmt = $db->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$current_user_id]);
    $updatedUser = $stmt->fetch();

    if ($updatedUser && $updatedUser['role'] === 'admin') {
        $flagFound = true;
        // Cleanup: reset alice's role back to 'user'
        $db->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$current_user_id]);
    }

    $updateMessage = 'Profile updated. Role is now: ' . htmlspecialchars($updatedUser['role'] ?? 'unknown');
}

// Current alice state
$db   = get_db();
$stmt = $db->prepare("SELECT * FROM users WHERE id=?");
$stmt->execute([$current_user_id]);
$aliceNow = $stmt->fetch();

$_flag_result = handle_inline_flag_submit(5);
html_open('Level 5 — Mass Assignment');
render_page_header('Level 5 — Mass Assignment', 'Injecting Unintended Parameters into POST Request', 5);
?>

<div class="context-bar">
    <div>Logged in as: <span><?= htmlspecialchars($aliceNow['username'] ?? 'alice') ?></span></div>
    <div>User ID: <span>1</span></div>
    <div>Current Role: <span style="color:<?= ($aliceNow['role'] ?? 'user') === 'admin' ? 'var(--white)' : 'var(--text-muted)' ?>;font-weight:<?= ($aliceNow['role'] ?? 'user') === 'admin' ? '700' : '400' ?>;"><?= htmlspecialchars($aliceNow['role'] ?? 'user') ?></span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level5.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-variable">$current_user_id</span> = <span class="php-string">1</span>; <span class="php-comment">// Alice</span>
<span class="php-keyword">if</span> (<span class="php-variable">$_SERVER</span>[<span class="php-string">'REQUEST_METHOD'</span>] === <span class="php-string">'POST'</span>) {
    <span class="php-variable">$db</span>       = <span class="php-function">get_db</span>();
    <span class="php-variable">$username</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'username'</span>] ?? <span class="php-string">''</span>;
    <span class="php-variable">$email</span>    = <span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>]    ?? <span class="php-string">''</span>;
    <span class="php-comment">// VULNERABLE: accepts 'role' directly from POST!</span>
    <span class="vuln-line"><span class="php-variable">$role</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'role'</span>] ?? <span class="php-string">'user'</span>;</span>

    <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
        <span class="php-string">"UPDATE users SET username=?, email=?, role=? WHERE id=?"</span>
    );
    <span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$username</span>, <span class="php-variable">$email</span>, <span class="php-variable">$role</span>, <span class="php-variable">$current_user_id</span>]);

    <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(<span class="php-string">"SELECT * FROM users WHERE id=?"</span>);
    <span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$current_user_id</span>]);
    <span class="php-variable">$user</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();
    <span class="php-keyword">echo</span> <span class="php-string">"Role is now: "</span> . <span class="php-variable">$user</span>[<span class="php-string">'role'</span>];
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The server reads <code>role</code> from <code>$_POST</code> without
            filtering. The HTML form only shows <code>username</code> and <code>email</code> fields — but nothing
            stops you from adding extra POST parameters (via DevTools, Burp, or JavaScript <code>fetch()</code>).
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Profile Update</h3>
        <div class="scenario">
            <strong>Scenario:</strong> Update your profile below. The form only shows <code>username</code>
            and <code>email</code> — but the server also accepts a <code>role</code> parameter. Add it!
        </div>

        <form method="POST" action="level5.php" id="profileForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control"
                       value="<?= htmlspecialchars($aliceNow['username'] ?? 'alice') ?>">
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="text" id="email" name="email" class="form-control"
                       value="<?= htmlspecialchars($aliceNow['email'] ?? 'alice@lab.local') ?>">
            </div>
            <div class="form-group">
                <label for="extra_role" style="color:var(--white);font-weight:600;">
                    Extra Parameter: <code>role</code>
                    <span style="font-size:0.8rem;color:var(--text-muted);">(Not in the original form — inject it!)</span>
                </label>
                <input type="text" id="extra_role" name="role" class="form-control"
                       placeholder="Try: admin"
                       style="border-color:var(--border-hi);">
            </div>
            <button type="submit" class="btn btn-primary">Update Profile</button>
        </form>

        <?php if ($submitted): ?>
        <div class="message <?= $flagFound ? 'success' : 'info' ?>">
            <?= $updateMessage ?>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">Mass assignment successful — you escalated your role to admin!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(5)) ?></div>
        <div class="message info" style="font-size:0.82rem;">Note: Your role has been automatically reset to <code>user</code> for lab integrity.</div>
        <?php endif; ?>
        <?php endif; ?>

        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:0.5rem;"><strong style="color:var(--text);">Alternative method — JavaScript fetch:</strong></p>
            <code style="display:block;font-size:0.78rem;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;">fetch('/level5.php', {
  method: 'POST',
  body: new URLSearchParams({
    username: 'alice',
    email: 'alice@lab.local',
    role: 'admin'   // &lt;-- injected!
  })
}).then(r =&gt; r.text()).then(console.log);</code>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(5)) ?>
<?= render_inline_flag_form(5, $_flag_result) ?>

<div class="navigation">
    <a href="level4.php" class="prev-link">&#8592; Level 4</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level6.php" class="next-link">Level 6 &rarr;</a>
</div>

<?php html_close(); ?>
