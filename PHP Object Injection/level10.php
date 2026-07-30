<?php
require_once __DIR__ . '/helpers.php';

$levelId    = 10;
$levelTitle = 'Signed Token WAF Bypass';
$prevLevel  = 9;
$nextLevel  = 0; // last level

// ── Gadget class (quiet file-read; name dodges the WAF) ──────
class AuditTrail {
    public $file = '';
    public function __destruct() {
        if ($this->file !== '') {
            echo @file_get_contents($this->file);   // ← file read on free
        }
    }
}

// Server-side signing key the attacker does NOT have.
const L10_SECRET_KEY = 'poi-l10-a7f3c9e14b6d2085-server-only';

// ── Challenge logic (the REAL vulnerable code) ───────────────
$token = $_POST['token'] ?? '';
$ran = false;
$captured = '';
$blocked = false;
$sigNote = '';
$b64err  = false;

if ($token !== '') {
    $ran   = true;
    $parts = explode('|', $token, 2);
    $b64   = $parts[0] ?? '';
    $sig   = $parts[1] ?? '';

    $payload = base64_decode($b64, true);
    if ($payload === false || $payload === '') {
        $b64err = true;
    } else {
        $expected = hash_hmac('sha256', $payload, L10_SECRET_KEY);
        // FLAW: the signature is only enforced when it is non-empty.
        if ($sig !== '' && !hash_equals($expected, $sig)) {
            $sigNote = 'signature present but invalid — rejected';
        } else {
            // Layer 2 WAF: block obvious RCE gadget names.
            if (preg_match('/system|exec|passthru|shell|popen|proc_open/i', $payload)) {
                $blocked = true;
            } else {
                ob_start();
                $obj = @unserialize($payload);   // ← SINK
                unset($obj);                     // AuditTrail::__destruct() fires
                gc_collect_cycles();
                $captured = ob_get_clean();
            }
        }
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
    <title>Level 10 — Signed Token WAF Bypass | PHP Object Injection Lab</title>
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
        <span class="level-badge">Level 10</span>
        <h1><?= htmlspecialchars($levelTitle) ?></h1>
        <span class="difficulty-badge difficulty-expert">Expert</span>
    </div>

    <div class="challenge-layout">

        <div class="code-panel">
            <h3>Vulnerable Source Code</h3>
            <div class="source-code">
                <pre><code><span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level10.php — signed audit-token processor</span>
<span class="php-keyword">class</span> <span class="php-function">AuditTrail</span> {
    <span class="php-keyword">public</span> <span class="php-variable">$file</span> = <span class="php-string">''</span>;
    <span class="php-keyword">public function</span> <span class="php-function">__destruct</span>() {
        <span class="php-keyword">echo</span> <span class="php-function">file_get_contents</span>(<span class="php-variable">$this</span>-&gt;file); <span class="php-comment">// file read</span>
    }
}

<span class="php-variable">$token</span> = <span class="php-variable">$_POST</span>[<span class="php-string">'token'</span>];        <span class="php-comment">// "base64(serialized)|signature"</span>
[<span class="php-variable">$b64</span>, <span class="php-variable">$sig</span>] = <span class="php-function">explode</span>(<span class="php-string">'|'</span>, <span class="php-variable">$token</span>, 2);
<span class="php-variable">$payload</span> = <span class="php-function">base64_decode</span>(<span class="php-variable">$b64</span>);
<span class="php-variable">$expected</span> = <span class="php-function">hash_hmac</span>(<span class="php-string">'sha256'</span>, <span class="php-variable">$payload</span>, <span class="php-variable">$KEY</span>);
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-variable">$sig</span> !== <span class="php-string">''</span> &amp;&amp; !<span class="php-function">hash_equals</span>(<span class="php-variable">$expected</span>, <span class="php-variable">$sig</span>)) <span class="php-function">deny</span>();</span> <span class="php-comment">// skipped if sig empty!</span>
<span class="php-keyword">if</span> (<span class="php-function">preg_match</span>(<span class="php-string">'/system|exec|passthru|shell|popen|proc_open/i'</span>, <span class="php-variable">$payload</span>)) <span class="php-function">deny</span>();
<span class="vuln-line"><span class="php-variable">$obj</span> = <span class="php-function">unserialize</span>(<span class="php-variable">$payload</span>);  <span class="php-comment">// sink</span></span><span class="php-keyword">?&gt;</span></code></pre>
            </div>
            <div class="vuln-annotation">
                <strong>Two flawed layers:</strong>&nbsp; The HMAC check is only enforced when the signature is
                <em>non-empty</em> — send an <strong>empty</strong> signature (trailing <code>|</code>) and it is skipped.
                The WAF then blocks RCE gadget names (<code>system</code>, <code>exec</code>, <code>shell</code>…), so use a
                quiet <strong>file-read</strong> gadget like <code>AuditTrail</code> instead. Point its <code>file</code> at
                <code>/var/secret/flag.txt</code>.
            </div>
        </div>

        <div class="challenge-panel">
            <h3>Challenge</h3>

            <div class="scenario">
                <p>An audit endpoint accepts a signed token <code>base64(serialized)|signature</code>. You do not
                know the signing key — but you do not need it.</p>
                <p>Bypass the signature check, dodge the WAF blacklist, and land a file-read gadget. The builder
                below can serialize + base64 your object (append the trailing <code>|</code> yourself).</p>
            </div>

            <form method="post" action="level10.php">
                <div class="form-group">
                    <label class="form-label" for="token_input">Signed token (POST) &mdash; <code>base64|signature</code></label>
                    <input
                        type="text"
                        id="token_input"
                        name="token"
                        class="form-control"
                        placeholder="Tzo...fQ==|"
                        value="<?= htmlspecialchars($token) ?>"
                        autocomplete="off"
                        spellcheck="false"
                    >
                </div>
                <div style="display:flex; gap:0.6rem; margin-top:0.75rem; flex-wrap:wrap;">
                    <button type="submit" class="btn btn-primary">Process Token</button>
                    <?php if ($token !== ''): ?>
                    <a href="level10.php" class="btn btn-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>

            <?php if ($flag): ?>
            <div class="flag-display">
                <h3>&#x1F3C6; Both Layers Bypassed!</h3>
                <p>Empty signature skipped the HMAC check; the file-read gadget slipped past the WAF and read the secret.</p>
                <code><?= htmlspecialchars($flag) ?></code>
                <p style="margin-top:0.75rem;"><a href="submit.php" style="color:#818cf8;">Submit this flag &rarr;</a></p>
            </div>
            <?php elseif ($b64err): ?>
            <div class="message error">Could not base64-decode the token. Format is <code>base64(serialized)|signature</code>.</div>
            <?php elseif ($sigNote !== ''): ?>
            <div class="message error"><?= htmlspecialchars($sigNote) ?>. Hint: leave the signature <em>empty</em> (trailing <code>|</code>).</div>
            <?php elseif ($blocked): ?>
            <div class="message error">WAF blocked the payload (matched <code>system|exec|passthru|shell|popen|proc_open</code>). Use a file-read gadget instead of an RCE one.</div>
            <?php elseif ($ran): ?>
            <div class="message error">Token processed, but the gadget did not read the secret. Point <code>AuditTrail::file</code> at <code>/var/secret/flag.txt</code>.</div>
            <?php endif; ?>

            <?php if ($ran && !$b64err): ?>
            <div class="output-section">
                <h4>Processing trace</h4>
                <div class="output-box">signature check : <?= $sigNote !== '' ? 'REJECTED' : 'skipped/passed' ?>
WAF filter      : <?= $blocked ? 'BLOCKED' : 'passed' ?>
gadget output   : <?= htmlspecialchars(trim($captured) === '' ? '(none)' : substr(trim($captured), 0, 400)) ?></div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <?= render_hint_section($hints) ?>
    <?= render_payload_builder() ?>
    <?= render_inline_flag_form($levelId, $_flag_result) ?>

    <div class="navigation">
        <a href="level<?= $prevLevel ?>.php" class="btn btn-secondary">&larr; Level <?= $prevLevel ?></a>
        <a href="submit.php" class="btn btn-secondary nav-center">Submit Flag</a>
        <a href="index.php" class="btn btn-secondary">&#x1F3C6; All Levels</a>
    </div>

</div>
</body>
</html>
