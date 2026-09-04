<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 8;
$levelTitle = 'Phar Deserialization';
$nextLevel  = 9;

// ── Gadget class baked into the phar metadata (shown in panel) ─
class PharGadget {
    public $file    = '';
    public $content = '';
    public function __wakeup() {
        if ($this->file !== '') {
            $this->content = @file_get_contents($this->file);
        }
    }
}

// ── Challenge logic (the REAL vulnerable code) ───────────────
$target = $_POST['gadget_file'] ?? '';
$ran = false;
$built = false;
$exists = false;
$captured = '';
$err = '';

if ($target !== '') {
    $ran = true;
    try {
        $dir = poi_scratch_dir();

        // (1) An attacker crafts a .phar whose METADATA is a PharGadget object.
        //     (Here the lab builds it from your chosen gadget target, modelling
        //      an uploaded "avatar" that is really a polyglot phar.)
        $src = $dir . '/build_' . getmypid() . '_' . bin2hex(random_bytes(3)) . '.phar';
        @unlink($src);
        $p = new Phar($src);
        $p->startBuffering();
        $p->addFromString('test.txt', 'avatar');
        $g = new PharGadget();
        $g->file = $target;                 // <-- attacker-controlled metadata
        $p->setMetadata($g);
        $p->setStub('<?php __HALT_COMPILER(); ?>');
        $p->stopBuffering();
        unset($p);
        // fresh copy so the metadata parses fresh in this process
        $fresh = $dir . '/avatar_' . bin2hex(random_bytes(6)) . '.phar';
        copy($src, $fresh);
        $built = true;

        // (2) The vulnerable app runs a file operation on a phar:// path.
        $exists = @file_exists('phar://' . $fresh . '/test.txt');   // ← SINK

        // On PHP < 8 that file op ALONE auto-unserialized the metadata and
        // fired __wakeup(). PHP 8 removed the implicit step, so the lab
        // reproduces it here to keep the technique learnable.
        $meta = (new Phar($fresh))->getMetadata();
        if ($meta instanceof PharGadget) {
            $captured = (string)$meta->content;
        }

        @unlink($src);
        @unlink($fresh);
    } catch (Throwable $e) {
        $err = $e->getMessage();
    }
}

$flag = poi_contains_secret($captured) ? get_flag_for_level($levelId) : '';

$hints = get_level_hints($levelId);
$_flag_result = handle_inline_flag_submit($levelId);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Level 8 — Phar Deserialization | PHP Object Injection Lab</title>
    <link rel="stylesheet" href="css/styles.css">
    <?= render_level_styles() ?>
</head>
<body>

<header class="header">
    <a href="index.php" class="back-btn">&larr; Back to Levels</a>
    <div class="header-title"><span style="color:var(--primary)">&#x1F9E9;</span> PHP Object Injection Lab</div>
    <a href="submit.php" class="submit-link">Submit Flag</a>
</header>

<div class="container">

    <div class="level-header">
        <span class="level-badge">Level 8</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-hard">Hard</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level8.php — avatar validator</span>
<span class="php-keyword">class</span> <span class="php-function">PharGadget</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$file</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__wakeup</span>() {
        <span class="php-variable">$this</span>-&gt;content = <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;file);
    }
}

<span class="php-comment">// attacker uploads a crafted .phar as their "avatar"</span>
<span class="php-variable">$path</span> = <span class="php-string">'uploads/'</span> . <span class="php-variable">$avatar</span>;
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-function">file_exists</span>(<span class="php-string">'phar://'</span> . <span class="php-variable">$path</span> . <span class="php-string">'/test.txt'</span>)) {</span>
    <span class="php-comment">// the phar:// file op deserializes the metadata -&gt; __wakeup()</span>
    <span class="php-function">accept_avatar</span>();
}<span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Phar deserialization:</strong>&nbsp; A phar archive stores a serialized metadata object.
                Any file operation on a <code>phar://</code> path parses the archive and unserializes that
                metadata — no explicit <code>unserialize()</code> call in sight. The lab builds the crafted phar
                from the gadget target you supply (simulating the malicious upload) and reproduces the classic
                pre-PHP-8 auto-deserialization.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>The avatar validator runs <code>file_exists()</code> on a <code>phar://</code> path built from
                an uploaded file. That is enough to deserialize the archive's <code>PharGadget</code> metadata and
                fire its <code>__wakeup()</code>.</p>
                <p>Choose the file the gadget should read. The secret is at <code>/var/secret/flag.txt</code>.</p>
            </div>

            <form method="post" action="level8.php">
                <div class="form-group">
                    <label class="form-label" for="gadget_input">Gadget target (metadata <code>file</code>)</label>
                    <input
                        type="text"
                        id="gadget_input"
                        name="gadget_file"
                        class="form-control"
                        placeholder="/var/secret/flag.txt"
                        value="<?= htmlspecialchars($target) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Build Phar &amp; Validate</button>
                    <?php if ($target !== ''): ?>
                    <a href="level8.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Metadata Deserialized!</h3>
                <p>The <code>phar://</code> file op fired <code>__wakeup()</code>, which read the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#6f9fb0;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($err !== ''): ?>
            <div class="message error">Phar build error: <?= htmlspecialchars($err) ?> (needs <code>phar.readonly=Off</code>).</div>
            <?php elseif ($ran): ?>
            <div class="message error">The gadget fired but did not read the secret. Point the metadata <code>file</code> at <code>/var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran && $err === ''): ?>
            <div class="output-section">
                <h4>Phar trace</h4>
                <div class="output-box">crafted phar built  : <?= $built ? 'yes' : 'no' ?>
file_exists(phar://) : <?= $exists ? 'true' : 'false' ?>
__wakeup() read      : <?= htmlspecialchars(trim($captured) === '' ? '(empty)' : substr(trim($captured), 0, 400)) ?></div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section($hints) ?>
    <?= render_payload_builder() ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="index.php" class="btn btn-secondary">&larr; Home</a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="level<?= $nextLevel ?>.php" class="btn btn-secondary">Level <?= $nextLevel ?> &rarr;</a>
    </div>

</div>
</body>
</html>
