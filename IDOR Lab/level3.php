<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$profile   = null;
$flagFound = false;
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submitted = true;
    // VULNERABLE: uses client-supplied user_id directly
    $user_id = (int)($_POST['user_id'] ?? 1);

    $db   = get_db();
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $profile = $stmt->fetch();

    if ($profile && ($profile['role'] === 'admin' || (int)$profile['id'] === 4)) {
        $flagFound = true;
    }
}

$_flag_result = handle_inline_flag_submit(3);
html_open('Level 3 — Hidden Form Field Tampering');
render_page_header('Level 3 — Hidden Form Field Tampering', 'Trusting Client-Supplied User Identity', 3);
?>

<div class="context-bar">
    <div>Logged in as: <span>alice</span></div>
    <div>User ID: <span>1</span></div>
    <div>Role: <span>user</span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level3.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-comment">// Trust user_id from POST form (hidden field)</span>
<span class="vuln-line"><span class="php-variable">$user_id</span> = (<span class="php-keyword">int</span>)(<span class="php-variable">$_POST</span>[<span class="php-string">'user_id'</span>] ?? <span class="php-string">1</span>);</span>

<span class="php-keyword">if</span> (<span class="php-variable">$_SERVER</span>[<span class="php-string">'REQUEST_METHOD'</span>] === <span class="php-string">'POST'</span>) {
    <span class="php-variable">$db</span>   = <span class="php-function">get_db</span>();
    <span class="php-comment">// VULNERABLE: uses client-supplied user_id directly</span>
    <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
        <span class="php-string">"SELECT * FROM users WHERE id = ?"</span>
    );
    <span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$user_id</span>]);
    <span class="php-variable">$profile</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();
    <span class="php-comment">// Display profile including email and role</span>
}
<span class="php-keyword">?&gt;</span>

<span class="php-comment">&lt;!-- In the HTML form: --&gt;</span>
<span class="php-keyword">&lt;form</span> method=<span class="php-string">"POST"</span><span class="php-keyword">&gt;</span>
    <span class="php-comment">&lt;!-- Hidden field — client can change this! --&gt;</span>
    <span class="vuln-line"><span class="php-keyword">&lt;input</span> type=<span class="php-string">"hidden"</span> name=<span class="php-string">"user_id"</span> value=<span class="php-string">"1"</span><span class="php-keyword">&gt;</span></span>
    <span class="php-keyword">&lt;button</span> type=<span class="php-string">"submit"</span><span class="php-keyword">&gt;</span>View Profile<span class="php-keyword">&lt;/button&gt;</span>
<span class="php-keyword">&lt;/form&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The server trusts the <code>user_id</code> submitted in the POST body.
            An attacker changes the value before submitting to access any user's profile. The server should
            use <code>$_SESSION['user_id']</code> instead.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Profile Viewer</h3>
        <div class="scenario">
            <strong>Scenario:</strong> A profile form contains a <code>user_id</code> field. In a real app
            this would be a hidden field — here it is visible so you can easily modify it.
            Change it from <code>1</code> (Alice) to another user's ID and submit.
        </div>

        <form method="POST" action="level3.php">
            <div class="form-group">
                <label for="user_id">
                    User ID
                    <span style="color:var(--danger);font-size:0.8rem;">(In a real app this is a hidden input — change this value!)</span>
                </label>
                <input type="number" id="user_id" name="user_id" class="form-control"
                       value="<?= $submitted ? htmlspecialchars((string)($_POST['user_id'] ?? 1)) : '1' ?>"
                       min="1" max="10">
            </div>
            <button type="submit" class="btn btn-primary">View Profile</button>
        </form>

        <?php if ($submitted && $profile): ?>
        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <table class="data-table">
                <tbody>
                    <tr><td style="color:var(--text-muted);">ID</td><td><?= htmlspecialchars((string)$profile['id']) ?></td></tr>
                    <tr><td style="color:var(--text-muted);">Username</td><td><?= htmlspecialchars($profile['username']) ?></td></tr>
                    <tr><td style="color:var(--text-muted);">Email</td><td><?= htmlspecialchars($profile['email']) ?></td></tr>
                    <tr><td style="color:var(--text-muted);">Role</td>
                        <td><span style="color:<?= $profile['role'] === 'admin' ? '#fca5a5' : '#6ee7b7' ?>;"><?= htmlspecialchars($profile['role']) ?></span></td>
                    </tr>
                </tbody>
            </table>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">You accessed the admin profile by manipulating the hidden field!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(3)) ?></div>
        <?php else: ?>
        <div class="message info">Profile loaded. Try changing <code>user_id</code> to reach the admin (ID: 4).</div>
        <?php endif; ?>
        <?php elseif ($submitted): ?>
        <div class="message error">User not found.</div>
        <?php endif; ?>

        <div style="margin-top:1rem;font-size:0.82rem;color:var(--text-muted);">
            <strong>Known users:</strong>
            <table class="data-table" style="margin-top:0.3rem;">
                <thead><tr><th>ID</th><th>Username</th><th>Role</th></tr></thead>
                <tbody>
                    <tr><td>1</td><td>alice</td><td>user</td></tr>
                    <tr><td>2</td><td>bob</td><td>user</td></tr>
                    <tr><td>3</td><td>charlie</td><td>user</td></tr>
                    <tr><td>4</td><td>admin</td><td style="color:#fca5a5;">admin</td></tr>
                    <tr><td>5</td><td>guest</td><td>user</td></tr>
                </tbody>
            </table>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(3)) ?>
<?= render_inline_flag_form(3, $_flag_result) ?>

<div class="navigation">
    <a href="level2.php" class="prev-link">&#8592; Level 2</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level4.php" class="next-link">Level 4 &rarr;</a>
</div>

<?php html_close(); ?>
