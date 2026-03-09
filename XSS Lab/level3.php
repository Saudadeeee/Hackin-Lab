<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 3;
$levelTitle = 'Stored XSS via Comments';
$prevLevel  = 2;
$nextLevel  = 4;

$commentsFile = __DIR__ . '/stored_comments.json';

$flag        = '';
$flagMessage = '';
$postMessage = '';
$postType    = '';

// ── Handle clear ─────────────────────────────────────────────
if (isset($_GET['clear'])) {
    file_put_contents($commentsFile, '[]');
    header('Location: level3.php');
    exit;
}

// ── Handle POST (stored XSS submission) ─────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $author  = trim($_POST['author']  ?? 'Anonymous');
    $comment = $_POST['comment'] ?? '';

    if ($comment !== '') {
        // Persist comment — intentionally NO sanitisation (this is the vulnerability)
        $comments   = json_decode(file_get_contents($commentsFile), true) ?? [];
        $comments[] = [
            'author' => $author,
            'text'   => $comment,
        ];
        file_put_contents($commentsFile, json_encode($comments, JSON_PRETTY_PRINT));

        // Server-side flag check on the comment being submitted
        if (verify_xss_payload($levelId, $comment)) {
            $flag        = get_flag_for_level($levelId);
            $flagMessage = 'XSS payload stored and detected server-side!';
        } else {
            $postMessage = 'Comment saved! (No XSS vector detected — try again.)';
            $postType    = 'info';
        }
    } else {
        $postMessage = 'Please enter a comment.';
        $postType    = 'error';
    }
}

// ── Load all stored comments ─────────────────────────────────
$comments = json_decode(file_get_contents($commentsFile), true) ?? [];

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 3 — Stored XSS via Comments | XSS Lab</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x26A1;</span> XSS Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 3</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-medium">Medium</span>
    </div>

    <div class="challenge-layout">

        <!-- ── Left: Source Code Panel ── -->
        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-variable">$commentsFile</span> = <span class="php-string">'stored_comments.json'</span>;

<span class="php-keyword">if</span> (<span class="php-variable">$_POST</span>[<span class="php-string">'comment'</span>] ?? <span class="php-string">''</span>) {
    <span class="php-variable">$comments</span> = json_decode(
        file_get_contents(<span class="php-variable">$commentsFile</span>), <span class="php-keyword">true</span>
    ) ?? [];
    <span class="php-variable">$comments</span>[] = [
        <span class="php-string">'author'</span> =&gt; <span class="php-variable">$_POST</span>[<span class="php-string">'author'</span>] ?? <span class="php-string">'Anonymous'</span>,
        <span class="php-string">'text'</span>   =&gt; <span class="php-variable">$_POST</span>[<span class="php-string">'comment'</span>],
    ];
    file_put_contents(
        <span class="php-variable">$commentsFile</span>,
        json_encode(<span class="php-variable">$comments</span>)
    );
}

<span class="php-variable">$comments</span> = json_decode(
    file_get_contents(<span class="php-variable">$commentsFile</span>), <span class="php-keyword">true</span>
) ?? [];
<span class="php-keyword">foreach</span> (<span class="php-variable">$comments</span> <span class="php-keyword">as</span> <span class="php-variable">$c</span>) {
<span class="vuln-line">    <span class="php-keyword">echo</span> <span class="php-string">"&lt;div class='comment'&gt;"</span>
        . <span class="php-string">"&lt;strong&gt;"</span> . <span class="php-variable">$c</span>[<span class="php-string">'author'</span>] . <span class="php-string">"&lt;/strong&gt;: "</span>
        . <span class="php-variable">$c</span>[<span class="php-string">'text'</span>]
        . <span class="php-string">"&lt;/div&gt;"</span>;</span>
}</code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Vulnerability:</strong>&nbsp;
                Both <code>$c['author']</code> and <code>$c['text']</code> are concatenated directly
                into the HTML output with <strong>no</strong> <code>htmlspecialchars()</code>.
                Comments persist in <code>stored_comments.json</code> and execute for
                <em>every visitor</em> who loads the page.
            </div>
        </div>

        <!-- ── Right: Challenge Panel ── -->
        <div class="challenge-panel">

            <div class="scenario">
                <h3>Scenario</h3>
                <p>A blog comment system stores user input in a JSON file and renders it
                back to the page without HTML encoding. Your payload is <strong>persisted</strong>
                on the server and will affect every subsequent visitor.</p>
                <p>Submit a comment containing an XSS payload. The server-side verifier checks
                the comment text for valid XSS vectors and awards the flag.</p>
            </div>

            <!-- Comment submission form -->
            <form method="post" action="level3.php">
                <div class="form-group">
                    <label class="form-label" for="author_input">Author Name</label>
                    <input
                        type="text"
                        id="author_input"
                        name="author"
                        class="form-control"
                        placeholder="Your name (optional)"
                        value="<?= htmlspecialchars($_POST['author'] ?? '') ?>"
                        autocomplete="off"
                    >
                </div>
                <div class="form-group">
                    <label class="form-label" for="comment_input">Comment (XSS Payload)</label>
                    <textarea
                        id="comment_input"
                        name="comment"
                        class="form-control"
                        placeholder="&lt;script&gt;alert(1)&lt;/script&gt;"
                        spellcheck="false"
                        rows="3"
                    ><?= htmlspecialchars($_POST['comment'] ?? '') ?></textarea>
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Post Comment</button>
                </div>
            </form>

            <!-- Flag / post result -->
            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Flag Captured!</h3>
                <p><?= htmlspecialchars($flagMessage) ?></p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem; font-size:0.8rem;">
                    <a href="submit.php">Submit this flag &rarr;</a>
                </p>
            </div>
            <?php elseif ($postMessage): ?>
            <div class="message <?= $postType ?>"><?= htmlspecialchars($postMessage) ?></div>
            <?php endif; ?>

            <!-- ── Stored comments output (actual XSS rendering) ── -->
            <div class="comments-section">
                <h4>Stored Comments
                    <span style="color:var(--text-muted); font-weight:400; font-size:0.8em;">
                        (<?= count($comments) ?> total)
                    </span>
                </h4>

                <?php if (empty($comments)): ?>
                <div class="message info" style="font-size:0.85rem;">No comments yet. Be the first!</div>
                <?php else: ?>
                <?php
                /*
                 * THIS IS THE ACTUAL VULNERABILITY:
                 * $c['author'] and $c['text'] are echoed WITHOUT htmlspecialchars().
                 * Any HTML/JS stored in these fields executes in the browser.
                 */
                foreach ($comments as $c) {
                    echo "<div class='comment-item'><strong>" . $c['author'] . "</strong>: " . $c['text'] . "</div>";
                }
                ?>
                <?php endif; ?>

                <?php if (!empty($comments)): ?>
                <div class="comment-actions">
                    <a href="level3.php?clear=1"
                       class="btn btn-danger btn-sm"
                       onclick="return confirm('Delete all stored comments?')">
                        Clear All Comments
                    </a>
                </div>
                <?php endif; ?>

                <p class="xss-sandbox-note">
                    Comments are stored in <code>stored_comments.json</code> with no sanitisation
                    and rendered raw — your payload persists and affects every page load.
                </p>
            </div>

        </div><!-- /.challenge-panel -->
    </div><!-- /.challenge-layout -->

    <?= render_hint_section($hints) ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div><!-- /.container -->
</body>
</html>
