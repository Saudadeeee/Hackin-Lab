<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$current_user_id = 1; // Alice — simulated session
$filename        = $_GET['filename'] ?? 'alice_doc.txt';
// Basic path-safety: strip slashes/dots so only bare filenames are accepted
$filename        = basename(str_replace(['/', '\\', '..'], '', $filename));
$upload          = null;
$flagFound       = false;

$db   = get_db();
// VULNERABLE: queries by filename only, no owner check
$stmt = $db->prepare("SELECT * FROM uploads WHERE filename = ?");
$stmt->execute([$filename]);
$upload = $stmt->fetch();

if ($upload && str_contains((string)$upload['content'], 'FLAG{')) {
    $flagFound = true;
}

// Alice's own uploads for context
$stmtMy = $db->prepare("SELECT id, filename, original_name FROM uploads WHERE owner_id = ?");
$stmtMy->execute([$current_user_id]);
$myUploads = $stmtMy->fetchAll();

$_flag_result = handle_inline_flag_submit(2);
html_open('Level 2 — IDOR File Download');
render_page_header('Level 2 — IDOR File Download', 'Accessing Another User\'s Uploaded File', 2);
?>

<div class="context-bar">
    <div>Logged in as: <span>alice</span></div>
    <div>User ID: <span>1</span></div>
    <div>Role: <span>user</span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level2.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-variable">$filename</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'filename'</span>] ?? <span class="php-string">'alice_doc.txt'</span>;

<span class="php-variable">$db</span> = <span class="php-function">get_db</span>();
<span class="php-comment">// VULNERABLE: queries by filename only, no owner check</span>
<span class="vuln-line"><span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(
    <span class="php-string">"SELECT * FROM uploads WHERE filename = ?"</span>
    <span class="php-comment">// Missing: AND owner_id = $current_user_id</span>
);</span>
<span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$filename</span>]);
<span class="php-variable">$upload</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();

<span class="php-keyword">if</span> (<span class="php-variable">$upload</span>) {
    <span class="php-function">header</span>(<span class="php-string">'Content-Type: text/plain'</span>);
    <span class="php-keyword">echo</span> <span class="php-variable">$upload</span>[<span class="php-string">'content'</span>];
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The query selects by <code>filename</code> alone. Any user who knows
            (or guesses) another user's filename can download their file. No <code>owner_id</code> filter exists.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>File Download</h3>
        <div class="scenario">
            <strong>Scenario:</strong> You are Alice. You uploaded <code>alice_doc.txt</code>.
            Bob also uploaded a confidential quarterly report. Can you download Bob's file?
        </div>

        <form method="GET" action="level2.php">
            <div class="form-group">
                <label for="filename">Filename (<code>?filename=</code>)</label>
                <input type="text" id="filename" name="filename" class="form-control"
                       value="<?= htmlspecialchars($filename) ?>"
                       placeholder="alice_doc.txt">
            </div>
            <button type="submit" class="btn btn-primary">Download File</button>
        </form>

        <?php if ($upload): ?>
        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.4rem;">
                File: <strong><?= htmlspecialchars($upload['filename']) ?></strong> &mdash;
                Original: <?= htmlspecialchars($upload['original_name']) ?> &mdash;
                Owner ID: <?= htmlspecialchars((string)$upload['owner_id']) ?>
            </div>
            <pre style="color:var(--text-muted);font-size:0.88rem;white-space:pre-wrap;word-break:break-all;"><?= htmlspecialchars($upload['content']) ?></pre>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">You downloaded a file belonging to another user!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(2)) ?></div>
        <?php endif; ?>
        <?php else: ?>
        <div class="message error">File not found.</div>
        <?php endif; ?>

        <div style="margin-top:1rem;">
            <h4 style="font-size:0.9rem;color:var(--text-muted);margin-bottom:0.5rem;">Your Uploaded Files (as Alice)</h4>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Filename</th><th>Original Name</th></tr></thead>
                <tbody>
                    <?php foreach ($myUploads as $u): ?>
                    <tr>
                        <td><?= htmlspecialchars((string)$u['id']) ?></td>
                        <td><code><?= htmlspecialchars($u['filename']) ?></code></td>
                        <td><?= htmlspecialchars($u['original_name']) ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p style="font-size:0.8rem;color:var(--text-muted);margin-top:0.5rem;">
                Other users have also uploaded files. Their filenames follow the same pattern...
            </p>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(2)) ?>
<?= render_inline_flag_form(2, $_flag_result) ?>

<div class="navigation">
    <a href="level1.php" class="prev-link">&#8592; Level 1</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level3.php" class="next-link">Level 3 &rarr;</a>
</div>

<?php html_close(); ?>
