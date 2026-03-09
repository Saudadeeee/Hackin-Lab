<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
$current_user_id = 1; // Alice — simulated session
$doc_id          = (int)($_GET['id'] ?? 1);
$doc             = null;
$flagFound       = false;

$db   = get_db();
$stmt = $db->prepare("SELECT * FROM documents WHERE id = ?");
$stmt->execute([$doc_id]);
$doc = $stmt->fetch();

if ($doc && str_contains((string)$doc['content'], 'FLAG{')) {
    $flagFound = true;
}

// Preload alice's documents for the context table
$stmtMy = $db->prepare("SELECT id, title, is_private FROM documents WHERE owner_id = ?");
$stmtMy->execute([$current_user_id]);
$myDocs = $stmtMy->fetchAll();

$_flag_result = handle_inline_flag_submit(1);
html_open('Level 1 — Basic IDOR');
render_page_header('Level 1 — Basic IDOR', 'Insecure Direct Object Reference', 1);
?>

<div class="context-bar">
    <div>Logged in as: <span>alice</span></div>
    <div>User ID: <span>1</span></div>
    <div>Role: <span>user</span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level1.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">require_once</span> <span class="php-string">'db.php'</span>;

<span class="php-comment">// Current user: Alice (simulated session)</span>
<span class="php-variable">$current_user_id</span> = <span class="php-string">1</span>;
<span class="php-variable">$doc_id</span> = (<span class="php-keyword">int</span>)(<span class="php-variable">$_GET</span>[<span class="php-string">'id'</span>] ?? <span class="php-string">1</span>);

<span class="php-variable">$db</span>   = <span class="php-function">get_db</span>();
<span class="vuln-line"><span class="php-variable">$stmt</span> = <span class="php-variable">$db</span>-><span class="php-function">prepare</span>(<span class="php-string">"SELECT * FROM documents WHERE id = ?"</span>);</span>
<span class="php-variable">$stmt</span>-><span class="php-function">execute</span>([<span class="php-variable">$doc_id</span>]);
<span class="php-variable">$doc</span> = <span class="php-variable">$stmt</span>-><span class="php-function">fetch</span>();

<span class="php-keyword">if</span> (<span class="php-variable">$doc</span>) {
    <span class="php-comment">// MISSING: no ownership check!</span>
    <span class="php-comment">// Should be: WHERE id = ? AND owner_id = ?</span>
    <span class="php-keyword">echo</span> <span class="php-variable">$doc</span>[<span class="php-string">'title'</span>] . <span class="php-string">': '</span> . <span class="php-variable">$doc</span>[<span class="php-string">'content'</span>];
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The query fetches <em>any</em> document by ID without checking
            <code>owner_id = $current_user_id</code>. Any authenticated user can read any document.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>Document Viewer</h3>
        <div class="scenario">
            <strong>Scenario:</strong> You are logged in as Alice (ID: 1). The document viewer loads documents
            by the <code>?id=</code> URL parameter. Can you read the admin's secret document?
        </div>

        <form method="GET" action="level1.php">
            <div class="form-group">
                <label for="id">Document ID (<code>?id=</code>)</label>
                <input type="number" id="id" name="id" class="form-control"
                       value="<?= htmlspecialchars((string)$doc_id) ?>" min="1" max="20">
            </div>
            <button type="submit" class="btn btn-primary">Fetch Document</button>
        </form>

        <?php if ($doc): ?>
        <div style="margin-top:1rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.4rem;">
                Document #<?= htmlspecialchars((string)$doc['id']) ?> &mdash;
                Owner ID: <?= htmlspecialchars((string)$doc['owner_id']) ?> &mdash;
                <?= $doc['is_private'] ? '<span style="color:#fca5a5;">Private</span>' : '<span style="color:#6ee7b7;">Public</span>' ?>
            </div>
            <div style="font-weight:600;margin-bottom:0.3rem;"><?= htmlspecialchars($doc['title']) ?></div>
            <div style="color:var(--text-muted);font-size:0.9rem;"><?= htmlspecialchars($doc['content']) ?></div>
        </div>
        <?php if ($flagFound): ?>
        <div class="message success">You accessed a document you should NOT have been able to read!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(1)) ?></div>
        <?php endif; ?>
        <?php else: ?>
        <div class="message error">Document not found.</div>
        <?php endif; ?>

        <div style="margin-top:1rem;">
            <h4 style="font-size:0.9rem;color:var(--text-muted);margin-bottom:0.5rem;">Your Documents (as Alice)</h4>
            <table class="data-table">
                <thead><tr><th>ID</th><th>Title</th><th>Visibility</th></tr></thead>
                <tbody>
                    <?php foreach ($myDocs as $d): ?>
                    <tr>
                        <td><?= htmlspecialchars((string)$d['id']) ?></td>
                        <td><?= htmlspecialchars($d['title']) ?></td>
                        <td><?= $d['is_private'] ? 'Private' : 'Public' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(1)) ?>
<?= render_inline_flag_form(1, $_flag_result) ?>

<div class="navigation">
    <a href="index.php" class="nav-link">&#8592; Lab Home</a>
    <a href="level2.php" class="next-link">Level 2 &rarr;</a>
</div>

<?php html_close(); ?>
