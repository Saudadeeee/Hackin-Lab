<?php
/**
 * Hackin-Lab · Lab Kit
 * ---------------------------------------------------------------------------
 * Shared rendering + teaching primitives for the newer labs.
 *
 * Design goal: a learner should never have to fuzz blindly. Every level can
 * show (a) the real source, (b) what each filter stage did to THEIR input,
 * (c) the exact string handed to the sink, (d) probes that test one hypothesis
 * at a time, (e) why the winning payload won, and (f) the correct fix.
 *
 * The page layout matches the original labs: source code panel on the left,
 * challenge panel on the right, hints + flag form + navigation underneath.
 */

/* =========================================================================
 * Small utilities
 * ===================================================================== */

function lk_esc(?string $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

/** Printable rendering of a raw byte string (control chars become escapes). */
function lk_visible(string $s, int $max = 400): string
{
    if (strlen($s) > $max) {
        $s = substr($s, 0, $max) . '...';
    }
    $out = '';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $ch = $s[$i];
        $o  = ord($ch);
        if ($ch === "\n") {
            $out .= '<span class="lk-ctl">\\n</span>';
        } elseif ($ch === "\r") {
            $out .= '<span class="lk-ctl">\\r</span>';
        } elseif ($ch === "\t") {
            $out .= '<span class="lk-ctl">\\t</span>';
        } elseif ($o < 0x20 || $o === 0x7f) {
            $out .= '<span class="lk-ctl">\\x' . sprintf('%02x', $o) . '</span>';
        } elseif ($ch === ' ') {
            $out .= '<span class="lk-sp">.</span>';
        } else {
            $out .= lk_esc($ch);
        }
    }
    return $out === '' ? '<span class="lk-empty">(empty string)</span>' : $out;
}

/* =========================================================================
 * Source-code rendering (auto syntax highlight - no hand-written spans)
 * ===================================================================== */

/**
 * Highlight source and render it with line numbers.
 * Lines listed in $vulnLines get the .vuln-line treatment.
 */
function lk_code(string $source, array $vulnLines = [], string $lang = 'php'): string
{
    $source = rtrim($source, "\n");
    $html   = $lang === 'php' ? lk_highlight_php($source) : lk_highlight_generic($source);
    $lines  = explode("\n", $html);

    $out = '<div class="source-code"><pre><code>';
    foreach ($lines as $i => $line) {
        $n   = $i + 1;
        $cls = in_array($n, $vulnLines, true) ? ' vuln-line' : '';
        $out .= '<span class="lk-line' . $cls . '">'
              . '<span class="lk-ln">' . str_pad((string)$n, 2, ' ', STR_PAD_LEFT) . '</span>'
              . ($line === '' ? ' ' : $line)
              . "</span>\n";
    }
    return $out . '</code></pre></div>';
}

function lk_highlight_php(string $source): string
{
    // token_get_all needs an opening tag; add one and drop it afterwards.
    $tokens = @token_get_all("<?php\n" . $source);
    if (!$tokens) {
        return lk_esc($source);
    }

    $out     = '';
    $skipped = false;

    foreach ($tokens as $tok) {
        if (is_string($tok)) {
            $out .= lk_esc($tok);
            continue;
        }
        $id   = $tok[0];
        $text = $tok[1];

        if (!$skipped && $id === T_OPEN_TAG) {   // drop the synthetic "<?php\n"
            $skipped = true;
            continue;
        }

        switch ($id) {
            case T_COMMENT:
            case T_DOC_COMMENT:
                $out .= '<span class="php-comment">' . lk_esc($text) . '</span>';
                break;
            case T_CONSTANT_ENCAPSED_STRING:
            case T_ENCAPSED_AND_WHITESPACE:
            case T_INLINE_HTML:
                $out .= '<span class="php-string">' . lk_esc($text) . '</span>';
                break;
            case T_VARIABLE:
                $out .= '<span class="php-variable">' . lk_esc($text) . '</span>';
                break;
            case T_LNUMBER:
            case T_DNUMBER:
                $out .= '<span class="lk-num">' . lk_esc($text) . '</span>';
                break;
            case T_WHITESPACE:
                $out .= lk_esc($text);
                break;
            case T_STRING:
                $out .= '<span class="php-function">' . lk_esc($text) . '</span>';
                break;
            default:
                if (defined('T_NAME_QUALIFIED') && $id === T_NAME_QUALIFIED) {
                    $out .= '<span class="php-function">' . lk_esc($text) . '</span>';
                } else {
                    $out .= '<span class="php-keyword">' . lk_esc($text) . '</span>';
                }
        }
    }
    return $out;
}

/** Light highlighter for JS / HTTP / SQL / config snippets. */
function lk_highlight_generic(string $source): string
{
    $s = lk_esc($source);
    $s = preg_replace('~(//[^\n]*)~', '<span class="php-comment">$1</span>', $s);
    $s = preg_replace(
        '~\b(function|const|let|var|return|if|else|await|async|new|class|throw|try|catch|SELECT|FROM|WHERE|AND|OR|UNION|null|true|false)\b~',
        '<span class="php-keyword">$1</span>',
        $s
    );
    return $s;
}

/* =========================================================================
 * Teaching primitives
 * ===================================================================== */

/** "How the sink actually parses your input" box - grammar, not payloads. */
function lk_model(string $title, string $html): string
{
    return '<div class="lk-box lk-model"><h4><span class="lk-tag">MENTAL MODEL</span>' . lk_esc($title)
         . '</h4><div class="lk-body">' . $html . '</div></div>';
}

/**
 * Filter pipeline trace: shows the learner's input travelling through every
 * transformation, so a rejected payload explains itself.
 *
 * @param array $stages [
 *   ['label' => 'raw input', 'value' => $raw],
 *   ['label' => "str_replace('<script>','')", 'value' => $s1,
 *    'note' => 'case-sensitive', 'verdict' => 'pass'|'block'|null],
 * ]
 */
function lk_pipeline(array $stages, string $title = 'What the server did to your input'): string
{
    if (!$stages) {
        return '';
    }
    $out  = '<div class="lk-box lk-pipeline"><h4><span class="lk-tag">TRACE</span>' . lk_esc($title)
          . '</h4><div class="lk-body">';
    $prev = null;
    foreach ($stages as $i => $st) {
        $val     = (string)($st['value'] ?? '');
        $verdict = $st['verdict'] ?? null;
        $changed = $prev !== null && $prev !== $val;
        $out .= '<div class="lk-stage' . ($verdict ? ' lk-stage-' . lk_esc($verdict) : '') . '">';
        $out .= '<div class="lk-stage-head"><span class="lk-step">' . ($i + 1) . '</span><code>'
              . lk_esc($st['label'] ?? '') . '</code>';
        if ($changed) {
            $out .= '<span class="lk-chip lk-chip-warn">modified</span>';
        } elseif ($prev !== null) {
            $out .= '<span class="lk-chip">unchanged</span>';
        }
        if ($verdict === 'block') {
            $out .= '<span class="lk-chip lk-chip-bad">blocked here</span>';
        } elseif ($verdict === 'pass') {
            $out .= '<span class="lk-chip lk-chip-good">passed</span>';
        }
        $out .= '</div><div class="lk-stage-val">' . lk_visible($val) . '</div>';
        if (!empty($st['note'])) {
            $out .= '<div class="lk-stage-note">' . $st['note'] . '</div>';
        }
        $out .= '</div>';
        $prev = $val;
    }
    return $out . '</div></div>';
}

/** The exact string handed to the sink, attacker-controlled part highlighted. */
function lk_sink(string $label, string $before, string $injected, string $after = ''): string
{
    return '<div class="lk-box lk-sink"><h4><span class="lk-tag lk-tag-red">SINK</span>' . lk_esc($label) . '</h4>'
         . '<div class="lk-body"><pre class="lk-sinkline">' . lk_esc($before)
         . '<span class="lk-inj">' . lk_visible($injected) . '</span>'
         . lk_esc($after) . '</pre></div></div>';
}

/**
 * Hypothesis probes. Each probe is one question about the target, not a
 * finished exploit - this is the habit the labs are trying to build.
 *
 * @param array $probes [['q' => 'Are single quotes escaped?', 'payload' => "'", 'learn' => '...']]
 */
function lk_probes(array $probes, string $param, string $method = 'GET', string $action = ''): string
{
    if (!$probes) {
        return '';
    }
    $out = '<div class="lk-box lk-probes"><h4><span class="lk-tag">PROBES</span>Test one hypothesis at a time</h4>'
         . '<div class="lk-body"><p class="lk-hintline">Each probe answers a single question about the target. '
         . 'Run them in order and read the trace above - that is how guessing turns into knowing.</p>'
         . '<div class="lk-probe-list">';
    foreach ($probes as $p) {
        $payload = (string)($p['payload'] ?? '');
        if (strtoupper($method) === 'GET') {
            $href = $action . '?' . rawurlencode($param) . '=' . rawurlencode($payload);
            $ctrl = '<a class="lk-probe-run" href="' . lk_esc($href) . '">run &rarr;</a>';
        } else {
            $ctrl = '<form method="post" action="' . lk_esc($action) . '" class="lk-probe-form">'
                  . '<input type="hidden" name="' . lk_esc($param) . '" value="' . lk_esc($payload) . '">'
                  . '<button type="submit" class="lk-probe-run">run &rarr;</button></form>';
        }
        $out .= '<div class="lk-probe"><div class="lk-probe-q">' . lk_esc($p['q'] ?? '') . '</div>'
              . '<div class="lk-probe-payload"><code>' . lk_visible($payload) . '</code>' . $ctrl . '</div>'
              . (!empty($p['learn']) ? '<div class="lk-probe-learn">' . $p['learn'] . '</div>' : '')
              . '</div>';
    }
    return $out . '</div></div></div>';
}

/** Post-success explanation: why THAT payload beat THAT filter. */
function lk_why(string $html): string
{
    return '<div class="lk-box lk-why"><h4><span class="lk-tag lk-tag-good">WHY IT WORKED</span></h4>'
         . '<div class="lk-body">' . $html . '</div></div>';
}

/** The correct fix, shown as vulnerable-vs-patched code. */
function lk_fix(string $bad, string $good, string $note = '', string $lang = 'php'): string
{
    return '<div class="lk-box lk-fix"><h4><span class="lk-tag">THE FIX</span>How this should have been written</h4>'
         . '<div class="lk-body"><div class="lk-fix-grid">'
         . '<div><div class="lk-fix-label lk-fix-bad">vulnerable</div>' . lk_code($bad, [], $lang) . '</div>'
         . '<div><div class="lk-fix-label lk-fix-good">patched</div>' . lk_code($good, [], $lang) . '</div>'
         . '</div>'
         . ($note !== '' ? '<div class="lk-fix-note">' . $note . '</div>' : '')
         . '</div></div>';
}

/** "What class of bug is this" primer, rendered under the code panel. */
function lk_theory(string $html): string
{
    return '<div class="lk-box lk-theory"><h4><span class="lk-tag">THEORY</span>Root cause</h4>'
         . '<div class="lk-body">' . $html . '</div></div>';
}

/* =========================================================================
 * Progress / flags
 * ===================================================================== */

function lk_cookie_name(string $slug): string
{
    return $slug . '_lab_progress';
}

function lk_completed(string $slug): array
{
    $raw = $_COOKIE[lk_cookie_name($slug)] ?? '';
    if ($raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        return [];
    }
    return array_values(array_filter(array_map('intval', $decoded)));
}

function lk_mark_complete(string $slug, int $level): void
{
    $done = lk_completed($slug);
    if (!in_array($level, $done, true)) {
        $done[] = $level;
        sort($done);
        setcookie(lk_cookie_name($slug), json_encode($done), time() + 86400 * 30, '/');
    }
}

/**
 * @return array{status:?string, message:string, already_completed:bool}
 */
function lk_handle_flag_submit(string $slug, int $levelId, string $expected): array
{
    $res = [
        'status'            => null,
        'message'           => '',
        'already_completed' => in_array($levelId, lk_completed($slug), true),
    ];

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $res;
    }
    $flag = trim((string)($_POST['submitted_flag'] ?? ''));
    if ($flag === '') {
        $res['status']  = 'error';
        $res['message'] = 'Please enter a flag.';
        return $res;
    }
    if ($expected !== '' && hash_equals($expected, $flag)) {
        lk_mark_complete($slug, $levelId);
        $res['status']            = 'success';
        $res['message']           = 'Correct! Flag accepted.';
        $res['already_completed'] = true;
    } else {
        $res['status']  = 'error';
        $res['message'] = 'Incorrect flag. Keep trying!';
    }
    return $res;
}

function lk_render_flag_form(int $levelId, array $result): string
{
    $status = $result['status'] ?? null;
    $done   = $result['already_completed'] ?? false;

    ob_start(); ?>
    <div class="inline-flag-submit">
        <h3>Submit Flag</h3>
        <div class="form-inner">
            <?php if ($status === 'success'): ?>
                <div class="message success"><?= lk_esc($result['message']) ?> &mdash; <a href="submit.php">view all progress &rarr;</a></div>
            <?php elseif ($status === 'error'): ?>
                <div class="message error"><?= lk_esc($result['message']) ?></div>
            <?php endif; ?>
            <?php if ($done && $status !== 'success'): ?>
                <div class="message info">Level <?= (int)$levelId ?> already completed. <a href="submit.php">View progress &rarr;</a></div>
            <?php endif; ?>
            <?php if (!$done || $status === 'error'): ?>
            <form method="POST" action="">
                <input type="hidden" name="_flag_submit" value="1">
                <div class="inline-flag-row">
                    <input type="text" name="submitted_flag" class="form-control" placeholder="FLAG{...}"
                           autocomplete="off" spellcheck="false" value="<?= lk_esc($_POST['submitted_flag'] ?? '') ?>">
                    <button type="submit" class="btn btn-primary">Check</button>
                </div>
            </form>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

function lk_render_hints(array $hints, string $title = 'Hints'): string
{
    if (!$hints) {
        return '';
    }
    static $scriptRendered = false;
    $id = uniqid('hint_', false);
    ob_start(); ?>
    <div class="hints" id="<?= $id ?>">
        <h3><?= lk_esc($title) ?></h3>
        <button class="hint-btn" data-hint-target="<?= $id ?>">Show Next Hint (0/<?= count($hints) ?>)</button>
        <ul class="hint-list">
            <?php foreach ($hints as $h): ?><li class="hint-item" hidden><?= $h ?></li><?php endforeach; ?>
        </ul>
    </div>
    <?php
    if (!$scriptRendered) {
        $scriptRendered = true; ?>
        <script>
        document.addEventListener('click', function (e) {
            if (!e.target.classList.contains('hint-btn')) return;
            const c = document.getElementById(e.target.getAttribute('data-hint-target'));
            const items = c.querySelectorAll('.hint-item[hidden]');
            const total = c.querySelectorAll('.hint-item').length;
            if (!items.length) return;
            items[0].removeAttribute('hidden');
            const shown = total - items.length + 1;
            e.target.textContent = shown < total ? 'Show Next Hint (' + shown + '/' + total + ')' : 'All hints shown';
            if (shown >= total) e.target.disabled = true;
        });
        </script>
    <?php }
    return ob_get_clean();
}

/* =========================================================================
 * Full level page renderer
 * ===================================================================== */

/**
 * Render one challenge page. Layout is fixed: source on the left, challenge
 * on the right, hints + flag form + nav underneath.
 *
 * @param array $c see the labs for the exact keys in use
 */
function lk_page(array $c): void
{
    $lab   = $c['lab'];
    $lvl   = (int)$c['level'];
    $total = (int)($lab['total'] ?? 10);
    $diff  = $c['difficulty'] ?? 'Medium';
    $flag  = (string)($c['flag'] ?? '');
    $res   = lk_handle_flag_submit($lab['slug'], $lvl, (string)($c['expected_flag'] ?? $flag));
    $prev  = $lvl > 1 ? $lvl - 1 : null;
    $next  = $lvl < $total ? $lvl + 1 : null;
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Level <?= $lvl ?> &mdash; <?= lk_esc($c['title']) ?> | <?= lk_esc($lab['name']) ?></title>
<link rel="stylesheet" href="css/styles.css">
<?= $c['extra_head'] ?? '' ?>
</head>
<body>
<header class="header">
    <div class="header-left">
        <h1><?= lk_esc($lab['icon'] ?? '') ?> <?= lk_esc($lab['name']) ?></h1>
        <p>Level <?= $lvl ?> of <?= $total ?> &mdash; <?= lk_esc($c['title']) ?></p>
    </div>
    <div class="header-right">
        <a href="index.php" class="back-btn">&larr; Levels</a>
        <a href="submit.php" class="submit-btn">Submit Flag</a>
    </div>
</header>

<div class="container">
    <div class="context-bar">
        <span class="level-num">LEVEL <?= $lvl ?></span>
        <span class="badge badge-<?= strtolower($diff) ?>"><?= lk_esc($diff) ?></span>
        <span class="text-muted"><?= lk_esc($c['title']) ?></span>
    </div>

    <div class="challenge-layout">

        <!-- LEFT: vulnerable source -->
        <div class="code-panel">
            <div class="panel-header"><span class="panel-label">Vulnerable Source Code</span></div>
            <?= lk_code((string)$c['code'], $c['vuln_lines'] ?? [], $c['lang'] ?? 'php') ?>
            <?php if (!empty($c['annotation'])): ?>
                <div class="vuln-annotation"><strong>Vulnerability:</strong>&nbsp; <?= $c['annotation'] ?></div>
            <?php endif; ?>
            <?php if (!empty($c['theory'])) echo lk_theory($c['theory']); ?>
            <?php if (!empty($c['fix'])) {
                echo lk_fix($c['fix']['bad'], $c['fix']['good'], $c['fix']['note'] ?? '', $c['fix']['lang'] ?? 'php');
            } ?>
        </div>

        <!-- RIGHT: challenge -->
        <div class="challenge-panel">
            <div class="panel-header"><span class="panel-label">Challenge</span></div>
            <div class="panel-body">
                <?php if (!empty($c['scenario'])): ?>
                    <div class="scenario"><?= $c['scenario'] ?></div>
                <?php endif; ?>

                <?php if (!empty($c['model'])) echo lk_model($c['model']['title'], $c['model']['html']); ?>

                <?= $c['form'] ?? '' ?>

                <?php if ($flag !== ''): ?>
                    <div class="flag-display">
                        <h3>&#x1F3C6; Flag Captured</h3>
                        <?php if (!empty($c['flag_msg'])): ?><p><?= $c['flag_msg'] ?></p><?php endif; ?>
                        <code><?= lk_esc($flag) ?></code>
                    </div>
                    <?php if (!empty($c['why'])) echo lk_why($c['why']); ?>
                <?php endif; ?>

                <?= $c['result'] ?? '' ?>

                <?php if (!empty($c['pipeline'])) echo lk_pipeline($c['pipeline']); ?>
                <?php if (!empty($c['sink'])) {
                    echo lk_sink($c['sink']['label'], $c['sink']['before'], $c['sink']['injected'], $c['sink']['after'] ?? '');
                } ?>
                <?php if (!empty($c['probes'])) {
                    echo lk_probes(
                        $c['probes']['items'],
                        $c['probes']['param'],
                        $c['probes']['method'] ?? 'GET',
                        $c['probes']['action'] ?? ''
                    );
                } ?>
            </div>
        </div>
    </div>

    <?= lk_render_hints($c['hints'] ?? []) ?>
    <?= lk_render_flag_form($lvl, $res) ?>

    <div class="navigation">
        <?php if ($prev): ?><a href="level<?= $prev ?>.php" class="btn btn-outline">&larr; Level <?= $prev ?></a><?php else: ?><span></span><?php endif; ?>
        <a href="index.php" class="btn btn-outline">All Levels</a>
        <?php if ($next): ?><a href="level<?= $next ?>.php" class="btn btn-outline">Level <?= $next ?> &rarr;</a><?php else: ?><span></span><?php endif; ?>
    </div>
</div>
<?= $c['extra_body'] ?? '' ?>
</body>
</html><?php
}

/* =========================================================================
 * Index + submit page renderers (identical shape across labs)
 * ===================================================================== */

function lk_index_page(array $lab, array $levels, string $intro, string $note = ''): void
{
    $done = lk_completed($lab['slug']);
    $pct  = count($levels) ? (int)round(count($done) / count($levels) * 100) : 0;
    ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= lk_esc($lab['name']) ?></title>
<link rel="stylesheet" href="css/styles.css">
</head>
<body>
<header class="header">
    <div class="header-left"><h1><?= lk_esc($lab['icon'] ?? '') ?> <?= lk_esc($lab['name']) ?></h1><p><?= lk_esc($lab['tagline'] ?? '') ?></p></div>
    <div class="header-right"><a href="submit.php" class="submit-btn">Submit Flag</a></div>
</header>
<div class="container">
    <div class="labs-hero">
        <h2><?= lk_esc($lab['name']) ?></h2>
        <p><?= $intro ?></p>
        <div class="lk-progress">
            <div class="lk-progress-track"><div class="lk-progress-fill" style="width:<?= $pct ?>%"></div></div>
            <span class="text-muted"><?= count($done) ?>/<?= count($levels) ?> solved</span>
        </div>
        <?php if ($note !== ''): ?><div class="whitebox-note"><?= $note ?></div><?php endif; ?>
    </div>
    <div class="level-grid">
        <?php foreach ($levels as $n => $m): ?>
        <a class="level-card<?= in_array($n, $done, true) ? ' lk-solved' : '' ?>" href="level<?= $n ?>.php">
            <div class="lk-card-top">
                <span class="level-num">LEVEL <?= $n ?></span>
                <span class="badge badge-<?= strtolower($m['difficulty']) ?>"><?= lk_esc($m['difficulty']) ?></span>
            </div>
            <h3><?= lk_esc($m['title']) ?></h3>
            <p><?= $m['desc'] ?></p>
            <?php if (!empty($m['skill'])): ?><div class="lk-skill">Teaches: <?= lk_esc($m['skill']) ?></div><?php endif; ?>
            <?php if (in_array($n, $done, true)): ?><div class="lk-solved-tag">solved</div><?php endif; ?>
        </a>
        <?php endforeach; ?>
    </div>
</div>
</body>
</html><?php
}

function lk_submit_page(array $lab, array $levels, callable $flagFor): void
{
    $msg = '';
    $type = '';
    if (isset($_GET['clear'])) {
        setcookie(lk_cookie_name($lab['slug']), '', time() - 3600, '/');
        header('Location: submit.php');
        exit;
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $lv = (int)($_POST['level'] ?? 0);
        $fl = trim((string)($_POST['flag'] ?? ''));
        if (!isset($levels[$lv])) {
            $msg = 'Pick a valid level.';
            $type = 'error';
        } elseif ($fl === '') {
            $msg = 'Enter a flag.';
            $type = 'error';
        } elseif (hash_equals($flagFor($lv), $fl)) {
            lk_mark_complete($lab['slug'], $lv);
            $msg = "Correct! Level $lv accepted.";
            $type = 'success';
        } else {
            $msg = 'Incorrect flag.';
            $type = 'error';
        }
    }
    $done = lk_completed($lab['slug']);
    ?><!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Submit Flag &mdash; <?= lk_esc($lab['name']) ?></title><link rel="stylesheet" href="css/styles.css"></head>
<body>
<header class="header">
    <div class="header-left"><h1><?= lk_esc($lab['icon'] ?? '') ?> <?= lk_esc($lab['name']) ?></h1><p>Flag submission &amp; progress</p></div>
    <div class="header-right"><a href="index.php" class="back-btn">&larr; Levels</a></div>
</header>
<div class="container submit-container">
    <?php if ($msg): ?><div class="message <?= $type ?>"><?= lk_esc($msg) ?></div><?php endif; ?>
    <div class="flag-form">
        <h3>Submit a flag</h3>
        <form method="post">
            <div class="form-group">
                <label class="form-label">Level</label>
                <select name="level" class="form-control">
                    <?php foreach ($levels as $n => $m): ?>
                    <option value="<?= $n ?>">Level <?= $n ?> &mdash; <?= lk_esc($m['title']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Flag</label>
                <input type="text" name="flag" class="form-control" placeholder="FLAG{...}" autocomplete="off">
            </div>
            <button class="btn btn-primary" type="submit">Submit</button>
        </form>
    </div>
    <div class="progress-grid">
        <?php foreach ($levels as $n => $m): $ok = in_array($n, $done, true); ?>
        <div class="progress-item<?= $ok ? ' lk-solved' : '' ?>">
            <span class="level-num">L<?= $n ?></span>
            <span><?= lk_esc($m['title']) ?></span>
            <span class="<?= $ok ? 'text-white' : 'text-faint' ?>"><?= $ok ? 'solved' : '&mdash;' ?></span>
        </div>
        <?php endforeach; ?>
    </div>
    <p style="margin-top:1.25rem"><a class="btn btn-outline" href="?clear=1">Reset progress</a></p>
</div>
</body>
</html><?php
}
