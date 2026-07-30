<?php
/**
 * SSRF Lab - Helper Functions
 * Utility functions for the Server-Side Request Forgery challenge lab.
 */

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{ssrf_basic}',
        2  => 'FLAG{ssrf_internal_service}',
        3  => 'FLAG{ssrf_blind}',
        4  => 'FLAG{ssrf_ip_encoding_bypass}',
        5  => 'FLAG{ssrf_open_redirect_chain}',
        6  => 'FLAG{ssrf_file_scheme}',
        7  => 'FLAG{ssrf_url_parser_confusion}',
        8  => 'FLAG{ssrf_cloud_metadata}',
        9  => 'FLAG{ssrf_hostname_bypass}',
        10 => 'FLAG{ssrf_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * The flag is awarded ONLY when the server-side fetch actually retrieved
 * content from the internal resource — i.e. the response body contains the
 * level's flag. This is NEVER a check against the user's raw input; it is a
 * check against what the vulnerable request brought back from the server.
 */
function ssrf_captured(int $levelId, string $response): bool {
    $flag = get_flag_for_level($levelId);
    return $flag !== '' && $response !== '' && strpos($response, $flag) !== false;
}

/**
 * Returns an array of 5 progressive hints for each level.
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'The server fetches whatever URL you provide and shows you the response. There is <strong>no validation at all</strong> on the target — it will happily request internal addresses.',
            'The interesting target lives on the server itself. The loopback address <code>127.0.0.1</code> (or the name <code>localhost</code>) points back at the machine running the app.',
            'There is an internal-only page called <code>internal.php</code> that returns a flag, but it only answers to requests coming from the loopback interface — you cannot reach it from your browser directly.',
            'Point the fetcher at the internal page and pass the level number: <code>internal.php?level=1</code>. Because the <em>server</em> makes the request, its source address is <code>127.0.0.1</code> and the page reveals the flag.',
            'Working payload: <code>?url=http://127.0.0.1/internal.php?level=1</code> &nbsp;|&nbsp; also works: <code>?url=http://localhost/internal.php?level=1</code>',
        ],
        2 => [
            'Servers often run private management interfaces that are only meant to be reached from the same host. Here that is <code>admin.php</code> — an internal status/admin panel bound to loopback.',
            'Opening <code>admin.php</code> in your own browser returns <strong>403 Forbidden</strong>, because your request does not originate from <code>127.0.0.1</code>.',
            'The SSRF sink turns the <em>server</em> into your proxy. When the server fetches <code>admin.php</code>, the request comes from loopback and the panel renders — flag included.',
            'Target the admin panel through the fetcher on the loopback interface: <code>http://127.0.0.1/admin.php</code>.',
            'Working payload: <code>?url=http://127.0.0.1/admin.php</code> &nbsp;|&nbsp; <code>?url=http://localhost/admin.php</code>',
        ],
        3 => [
            'This is <strong>Blind SSRF</strong>: the app makes the request for you but <em>never shows you the response body</em>. You only see a generic "request sent" confirmation.',
            'Even though you cannot see the body, the internal service still receives and processes the request. There is a loopback-only endpoint <code>beacon.php</code> that logs every hit it gets.',
            'The server-side code fetches your URL and inspects the response <em>on the server</em> (you just do not get to see it). If the response proves the internal beacon was reached, the level confirms it and awards the flag.',
            'Aim the fetcher at the internal beacon on loopback: <code>http://127.0.0.1/beacon.php</code>. The page will confirm the hit was recorded server-side.',
            'Working payload: <code>?url=http://127.0.0.1/beacon.php</code> &nbsp;|&nbsp; <code>?url=http://localhost/beacon.php?level=3</code>',
        ],
        4 => [
            'This level adds a <strong>host blocklist</strong>. Before fetching, it rejects any URL whose text contains <code>localhost</code> or <code>127.0.0.1</code>. The check is a naive string match on those two exact spellings.',
            'An IPv4 address has many equivalent representations. The blocklist only knows the dotted-quad <code>127.0.0.1</code> — it does not understand the <em>value</em> behind it.',
            'Try alternate encodings of loopback: the shorthand <code>127.1</code>, the integer <code>0</code>, the 32-bit decimal <code>2130706433</code>, or the IPv6 form <code>[::1]</code>. curl resolves all of them to the local host.',
            'None of those strings contain the literal <code>127.0.0.1</code> or <code>localhost</code>, so the filter waves them through — yet the connection still lands on the internal service.',
            'Working payloads: <code>?url=http://127.1/internal.php?level=4</code> &nbsp;|&nbsp; <code>?url=http://2130706433/internal.php?level=4</code> &nbsp;|&nbsp; <code>?url=http://[::1]/internal.php?level=4</code> &nbsp;|&nbsp; <code>?url=http://0/internal.php?level=4</code>',
        ],
        5 => [
            'The allowlist here only inspects the <strong>host of the URL you submit</strong>. It permits the trusted feed host <code>feed.local</code> and blocks everything else — but the fetcher <em>follows HTTP redirects</em>.',
            'A URL on the allowed host can still send the fetcher somewhere else. The app ships an open redirector at <code>http://feed.local/redirector.php</code> that 302-redirects to any <code>?url=</code> you give it.',
            'Chain them: submit a <code>feed.local</code> URL (which passes the allowlist) that redirects to the internal page. The allowlist checked only the <em>first</em> hop; curl transparently follows the 302 to loopback.',
            'Point the redirector at the internal endpoint: <code>redirector.php?url=http://127.0.0.1/internal.php?level=5</code>, hosted on the trusted <code>feed.local</code>.',
            'Working payload: <code>?url=http://feed.local/redirector.php?url=http://127.0.0.1/internal.php?level=5</code>',
        ],
        6 => [
            'The fetcher does not restrict the URL <strong>scheme</strong>. It is meant for <code>http://</code>, but it never checks — so other protocol handlers are fair game.',
            'PHP stream wrappers include <code>file://</code>, which reads local files straight off the server\'s disk. That turns the SSRF into an arbitrary file read.',
            'A secret was baked onto the server filesystem at <code>/var/secret/flag6.txt</code>, outside the web root, unreachable over HTTP.',
            'Use the <code>file://</code> scheme to read it directly through the fetcher — no HTTP involved.',
            'Working payload: <code>?url=file:///var/secret/flag6.txt</code>',
        ],
        7 => [
            'The allowlist wants the host to be <code>example.com</code>. It extracts the authority (everything between <code>://</code> and the next <code>/</code>) and checks whether <code>example.com</code> appears in it — a substring test, not real parsing.',
            'The URL authority can carry <em>userinfo</em> before an <code>@</code>: in <code>http://user@host/</code>, everything before the <code>@</code> is credentials and the real host is what comes <strong>after</strong> it.',
            'So <code>http://example.com@127.0.0.1/</code> has the string <code>example.com</code> sitting in the userinfo (passing the naive check), while the actual connection is made to <code>127.0.0.1</code>.',
            'Append the internal path and level: the fetcher connects to <code>127.0.0.1</code> and pulls <code>internal.php?level=7</code>, even though the filter believed the host was <code>example.com</code>.',
            'Working payloads: <code>?url=http://example.com@127.0.0.1/internal.php?level=7</code> &nbsp;|&nbsp; also try the fragment trick: <code>?url=http://127.0.0.1/internal.php?level=7%23.example.com</code>',
        ],
        8 => [
            'Cloud instances expose a metadata service at the link-local address <code>169.254.169.254</code>. Applications with SSRF can be tricked into querying it to steal instance credentials.',
            'This lab mocks that endpoint. It is reachable <em>only from inside the server</em> — your browser cannot route to <code>169.254.169.254</code>, but the vulnerable fetcher can.',
            'The classic path mirrors AWS: <code>/latest/meta-data/iam/security-credentials/</code> followed by the role name. This lab\'s role is <code>ssrf-lab-role</code>.',
            'Have the server request the credentials document for that role; the mock returns a JSON blob containing the leaked secret.',
            'Working payload: <code>?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ssrf-lab-role</code>',
        ],
        9 => [
            'The allowlist here decides trust by <strong>substring</strong>: it accepts the request if the hostname <em>contains</em> the string <code>corp-internal</code>, assuming that only its own internal servers match.',
            'A substring check on a hostname is easy to satisfy from the outside — you control your own DNS names, and any label that includes the magic substring passes.',
            'The lab provides an attacker-controlled hostname that both contains <code>corp-internal</code> and resolves to loopback: <code>corp-internal.attacker.local</code>. (Also available: <code>intranet.attacker.local</code> for the substring <code>intranet</code>.)',
            'Because the name contains <code>corp-internal</code> it passes the allowlist, and because it maps to <code>127.0.0.1</code> the fetch still lands on the internal service.',
            'Working payload: <code>?url=http://corp-internal.attacker.local/internal.php?level=9</code>',
        ],
        10 => [
            'This is a layered "WAF". Layer 1 requires the scheme to be <code>http</code>/<code>https</code> (so <code>file://</code> is out). Layer 2 rejects the URL if it contains <code>127.0.0.1</code>, <code>localhost</code>, <code>::1</code>, or <code>169.254</code>. Layer 3 rejects the keywords <code>metadata</code> and <code>@</code>.',
            'Each earlier trick is individually blocked: the file scheme (L6), the loopback literals (L4), the userinfo <code>@</code> (L7), and the metadata host (L8) are all caught by one layer or another.',
            'But Layer 2 only blocks specific <em>spellings</em> of loopback. The 32-bit decimal encoding of <code>127.0.0.1</code> is <code>2130706433</code> — it contains none of the blocked strings, uses the <code>http</code> scheme, and has no <code>@</code> or <code>metadata</code>.',
            'Combine what survives every layer: <code>http</code> scheme + decimal-IP loopback + the plain internal path. That single vector slips past all three filters at once.',
            'Working payload: <code>?url=http://2130706433/internal.php?level=10</code>',
        ],
    ];
    return $hints[$levelId] ?? [];
}

/**
 * Renders a progressive hint section with a "Show Next Hint" button.
 * Each call shares the same JS listener (rendered only once via static flag).
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
    if (!empty($_COOKIE['ssrf_lab_progress'])) {
        $decoded = json_decode($_COOKIE['ssrf_lab_progress'], true);
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
            setcookie('ssrf_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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
    $status          = $result['status'] ?? null;
    $message         = $result['message'] ?? '';
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
