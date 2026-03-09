<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
// Read role from cookie — NOT validated server-side!
$user_role = $_COOKIE['user_role'] ?? 'user';
$user_id   = $_COOKIE['user_id']   ?? '1';

$flagFound  = false;
$adminUsers = [];

if ($user_role === 'admin') {
    $flagFound = true;
    $db        = get_db();
    $stmt      = $db->query("SELECT username, email, role FROM users");
    $adminUsers = $stmt->fetchAll();
}

$_flag_result = handle_inline_flag_submit(6);
html_open('Level 6 — Cookie Role Forgery');
render_page_header('Level 6 — Cookie Role Forgery', 'Vertical Privilege Escalation via Cookie Manipulation', 6);
?>

<div class="context-bar">
    <div>Cookie <code>user_id</code>: <span><?= htmlspecialchars((string)$user_id) ?></span></div>
    <div>Cookie <code>user_role</code>: <span style="color:<?= $user_role === 'admin' ? 'var(--white)' : 'var(--text-muted)' ?>;font-weight:<?= $user_role === 'admin' ? '700' : '400' ?>;"><?= htmlspecialchars($user_role) ?></span></div>
    <div>Access Level: <span style="color:<?= $user_role === 'admin' ? 'var(--white)' : 'var(--text-faint)' ?>;font-weight:<?= $user_role === 'admin' ? '700' : '400' ?>;"><?= $user_role === 'admin' ? 'Admin' : 'User' ?></span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level6.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// Read role from cookie - NOT validated server-side!</span>
<span class="vuln-line"><span class="php-variable">$user_role</span> = <span class="php-variable">$_COOKIE</span>[<span class="php-string">'user_role'</span>] ?? <span class="php-string">'user'</span>;</span>
<span class="vuln-line"><span class="php-variable">$user_id</span>   = <span class="php-variable">$_COOKIE</span>[<span class="php-string">'user_id'</span>]   ?? <span class="php-string">'1'</span>;</span>

<span class="php-keyword">if</span> (<span class="php-variable">$user_role</span> === <span class="php-string">'admin'</span>) {
    <span class="php-comment">// Show admin panel</span>
    <span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;
    <span class="php-variable">$db</span>   = <span class="php-function">get_db</span>();
    <span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">query</span>(
        <span class="php-string">"SELECT username, email, role FROM users"</span>
    );
    <span class="php-variable">$admins</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetchAll</span>();
    <span class="php-comment">// Display all user data (admin privilege)</span>
} <span class="php-keyword">else</span> {
    <span class="php-keyword">echo</span> <span class="php-string">"Access denied. You are: "</span>
       . <span class="php-variable">$user_role</span>;
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The server reads the user's role from a <em>client-controlled</em>
            cookie with no HMAC, signature, or server-side session lookup. Any user can set
            <code>user_role=admin</code> in their browser to gain admin access.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Access Control Panel</h3>
        <div class="scenario">
            <strong>Scenario:</strong> The application stores your role in a cookie. No server-side validation
            exists. Change the <code>user_role</code> cookie from <code>user</code> to <code>admin</code>
            to gain access to the admin panel.
        </div>

        <?php if ($user_role === 'admin'): ?>
        <div class="message success">Admin access granted via cookie manipulation!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(6)) ?></div>
        <h4 style="font-size:0.9rem;margin:0.75rem 0 0.5rem;">User Database (Admin View)</h4>
        <table class="data-table">
            <thead><tr><th>Username</th><th>Email</th><th>Role</th></tr></thead>
            <tbody>
                <?php foreach ($adminUsers as $u): ?>
                <tr>
                    <td><?= htmlspecialchars($u['username']) ?></td>
                    <td><?= htmlspecialchars($u['email']) ?></td>
                    <td><span style="color:<?= $u['role'] === 'admin' ? 'var(--white)' : 'var(--text-muted)' ?>;font-weight:<?= $u['role'] === 'admin' ? '700' : '400' ?>;"><?= htmlspecialchars($u['role']) ?></span></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
        <div class="message error">Access denied. You are: <strong><?= htmlspecialchars($user_role) ?></strong></div>
        <p style="color:var(--text-muted);font-size:0.9rem;margin:0.75rem 0;">
            You need to modify your <code>user_role</code> cookie to gain admin access.
        </p>
        <?php endif; ?>

        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:0.75rem;"><strong style="color:var(--text);">How to forge the cookie — choose one method:</strong></p>

            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;"><strong style="color:var(--text);">Method 1 — Browser Console:</strong></p>
            <code style="display:block;font-size:0.82rem;color:#c9d1d9;background:var(--code-bg);padding:0.5rem;border-radius:4px;margin-bottom:0.75rem;">document.cookie = "user_role=admin; path=/";</code>

            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;"><strong style="color:var(--text);">Method 2 — DevTools:</strong></p>
            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.75rem;">
                DevTools (F12) &rarr; Application &rarr; Cookies &rarr; find <code>user_role</code> &rarr; double-click value &rarr; type <code>admin</code> &rarr; refresh.
            </p>

            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;"><strong style="color:var(--text);">Method 3 — Quick Set (click button):</strong></p>
            <button onclick="document.cookie='user_role=admin; path=/'; document.cookie='user_id=4; path=/'; location.reload();"
                    class="btn btn-primary" style="font-size:0.82rem;margin-bottom:0.5rem;">
                Set user_role=admin Cookie &amp; Reload
            </button>
            <button onclick="document.cookie='user_role=user; path=/'; document.cookie='user_id=1; path=/'; location.reload();"
                    class="btn" style="font-size:0.82rem;background:var(--surface2);color:var(--text);">
                Reset Cookie (user_role=user)
            </button>
        </div>

        <div style="margin-top:0.75rem;font-size:0.8rem;color:var(--text-muted);">
            <strong>Current Cookie Header:</strong>
            <code style="display:block;margin-top:0.3rem;word-break:break-all;color:#c9d1d9;">
                <?= htmlspecialchars($_SERVER['HTTP_COOKIE'] ?? '(no cookies set)') ?>
            </code>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(6)) ?>
<?= render_inline_flag_form(6, $_flag_result) ?>

<div class="navigation">
    <a href="level5.php" class="prev-link">&#8592; Level 5</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level7.php" class="next-link">Level 7 &rarr;</a>
</div>

<?php html_close(); ?>
