<?php
/**
 * PHP Object Injection Lab - Helper Functions
 * Shared utilities for the insecure-deserialization challenge lab.
 */

/* ------------------------------------------------------------------ *
 *  Sandboxed secret + gadget "effect" detection
 *  Every level bakes its secret at /var/secret/flag.txt. A successful
 *  gadget trigger reaches that file (reads it, or runs a command that
 *  prints it). The level page captures the gadget's NATURAL side effect
 *  — the bytes it echoed, or the property it populated — and checks for
 *  the secret marker. The flag is awarded because the exploit really
 *  produced the secret, NOT by string-matching the flag itself.
 * ------------------------------------------------------------------ */

const POI_SECRET_MARKER = 'POI_SECRET{';

/** Absolute path of the baked secret the gadgets are meant to reach. */
function poi_secret_path(): string {
    // Baked by the Dockerfile at /var/secret/flag.txt (outside the doc-root).
    // POI_SECRET_FILE lets the test harness point at a local copy under `php -S`
    // without ever shipping a web-reachable secret inside the document root.
    $env = getenv('POI_SECRET_FILE');
    if ($env && is_file($env)) return $env;
    return '/var/secret/flag.txt';
}

/** True only if a gadget effect actually reached the baked secret. */
function poi_contains_secret($data): bool {
    return strpos((string)$data, POI_SECRET_MARKER) !== false;
}

/** Writable scratch dir for the phar level's crafted archives (cross-platform). */
function poi_scratch_dir(): string {
    $dir = is_dir('/tmp/poi_phar') ? '/tmp/poi_phar' : sys_get_temp_dir() . '/poi_phar';
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    return $dir;
}

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{poi_property_injection}',
        2  => 'FLAG{poi_destruct_file_read}',
        3  => 'FLAG{poi_wakeup_gadget}',
        4  => 'FLAG{poi_tostring_gadget}',
        5  => 'FLAG{poi_pop_chain}',
        6  => 'FLAG{poi_type_juggling}',
        7  => 'FLAG{poi_wakeup_bypass}',
        8  => 'FLAG{poi_phar_deserialization}',
        9  => 'FLAG{poi_rce_chain}',
        10 => 'FLAG{poi_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Returns an array of 5 progressive hints for each level.
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'The page calls <code>unserialize()</code> on the raw <code>account</code> parameter, then checks <code>$obj->isAdmin === true</code>. You fully control every property that comes out of <code>unserialize()</code>.',
            'PHP\'s serialization format for an object is <code>O:&lt;len&gt;:"ClassName":&lt;propCount&gt;:{ properties }</code>. The <code>len</code> is the byte length of the class name.',
            'The class is <code>Account</code> (7 letters). It has two properties: <code>username</code> (string) and <code>isAdmin</code> (boolean). A boolean <code>true</code> serializes as <code>b:1;</code>.',
            'Build an <code>Account</code> object whose <code>isAdmin</code> property is boolean <code>true</code>. The strict <code>=== true</code> check means you must send a real boolean, not the string <code>"1"</code>.',
            'Working payload: <code>O:7:"Account":2:{s:8:"username";s:5:"guest";s:7:"isAdmin";b:1;}</code> &nbsp;(paste into the <code>account</code> field).',
        ],
        2 => [
            'The <code>TempFile</code> class has a <code>__destruct()</code> magic method that runs <code>@file_get_contents($this->path)</code> when the object is destroyed. This is a "file read gadget".',
            'Because you control the serialized object, you control <code>$this->path</code>. Point it at the baked secret: <code>/var/secret/flag.txt</code> (20 bytes).',
            'Object format: <code>O:&lt;len&gt;:"TempFile":&lt;count&gt;:{ &lt;properties&gt; }</code>. <code>TempFile</code> is 8 bytes. The single property is <code>path</code> (4 bytes).',
            'A string value is encoded <code>s:&lt;byteLength&gt;:"value";</code>. So the path becomes <code>s:20:"/var/secret/flag.txt";</code>.',
            'Working payload: <code>O:8:"TempFile":1:{s:4:"path";s:20:"/var/secret/flag.txt";}</code> &nbsp;(submit as the <code>blob</code> field).',
        ],
        3 => [
            'The <code>SessionStore</code> class runs its dangerous read inside <code>__wakeup()</code> — which PHP calls <em>automatically, during <code>unserialize()</code></em>, before you ever touch the object.',
            'The gadget reads <code>$this->file</code>. Set that property to the baked secret path <code>/var/secret/flag.txt</code>.',
            '<code>SessionStore</code> is 12 bytes. The property name <code>file</code> is 4 bytes; the path value is 20 bytes.',
            'Assemble: <code>O:12:"SessionStore":1:{ &lt;file property&gt; }</code> with the <code>file</code> property set to the secret path.',
            'Working payload: <code>O:12:"SessionStore":1:{s:4:"file";s:20:"/var/secret/flag.txt";}</code>',
        ],
        4 => [
            'The app builds a preview by concatenating your object into a string: <code>"Preview: " . $obj</code>. That string cast invokes <code>Template::__toString()</code>, which reads a file.',
            '<code>__toString()</code> returns <code>@file_get_contents($this->view)</code>. You control <code>view</code>, so aim it at <code>/var/secret/flag.txt</code>.',
            '<code>Template</code> is 8 bytes. The property <code>view</code> is 4 bytes; the secret path is 20 bytes.',
            'Any code path that echoes, prints, or string-concatenates the object will fire <code>__toString()</code>. You do not need a destructor here.',
            'Working payload: <code>O:8:"Template":1:{s:4:"view";s:20:"/var/secret/flag.txt";}</code>',
        ],
        5 => [
            'This is a <strong>POP chain</strong> (Property-Oriented Programming). One gadget\'s property holds a <em>second</em> object, and the first gadget\'s magic method calls a method on the second.',
            'Outer class <code>Logger</code> has <code>__destruct()</code> that does <code>$this->writer->flush()</code>. Inner class <code>FileViewer</code> has a <code>flush()</code> method that reads <code>$this->source</code>.',
            'So you nest a <code>FileViewer</code> (with <code>source</code> = the secret path) inside the <code>writer</code> property of a <code>Logger</code>.',
            'Nested objects have NO trailing semicolon: the inner <code>O:...:{...}</code> sits directly as the property value. <code>Logger</code>=6 bytes, <code>FileViewer</code>=10 bytes, <code>source</code>=6 bytes.',
            'Working payload: <code>O:6:"Logger":1:{s:6:"writer";O:10:"FileViewer":1:{s:6:"source";s:20:"/var/secret/flag.txt";}}</code>',
        ],
        6 => [
            'After <code>unserialize()</code>, the login check is <code>if ($token->password == $ADMIN_HASH)</code> — a <strong>loose</strong> <code>==</code> comparison. The stored hash is a "magic hash" that starts with <code>0e</code> followed by only digits.',
            'PHP\'s <code>==</code> treats two strings that both look like <code>0e[digits]</code> as scientific notation: <code>0e...</code> equals <code>0 * 10^... = 0</code>. So any two such strings are "equal".',
            'You control <code>$token->password</code> through the injected object. Set it to a different <code>0e</code>-magic-hash string and the loose comparison becomes <code>0 == 0</code> &rarr; true.',
            'Class is <code>AuthToken</code> (9 bytes); properties <code>user</code> and <code>password</code>. A known magic hash: <code>0e830400451993494058024219903391</code> (32 bytes, the md5 of <code>240610708</code>).',
            'Working payload (into the <code>auth_token</code> field): <code>O:9:"AuthToken":2:{s:4:"user";s:5:"admin";s:8:"password";s:32:"0e830400451993494058024219903391";}</code>',
        ],
        7 => [
            'The <code>SecureSession</code> class "defends itself": its <code>__wakeup()</code> resets <code>$this->file</code> to a harmless default every time the object is unserialized. A normal payload gets sanitized.',
            'CVE-2016-7124: in PHP before 7.0.10, if the object header declares <em>more</em> properties than are actually present, the engine skips <code>__wakeup()</code> entirely — your malicious property survives unsanitized.',
            'So take a valid object and bump the property count. The real object has 1 property; declare 2: <code>O:13:"SecureSession":<strong>2</strong>:{ ...one property... }</code>.',
            'The surviving <code>file</code> property should point at <code>/var/secret/flag.txt</code>. Because <code>__wakeup()</code> never runs, it never gets reset. (This lab reproduces the pre-7.0.10 engine behaviour so you can practise the technique on PHP 8.2.)',
            'Working payload: <code>O:13:"SecureSession":2:{s:4:"file";s:20:"/var/secret/flag.txt";}</code> &nbsp;— note the count is 2 but only one property is listed.',
        ],
        8 => [
            'This is <strong>Phar deserialization</strong>. When PHP touches a <code>phar://</code> path with a file operation, it parses the archive — and (historically) automatically <code>unserialize()</code>s the archive\'s embedded metadata object.',
            'The gadget baked into the archive is <code>PharGadget</code>; its <code>__wakeup()</code> reads <code>$this->file</code>. You control that property via the metadata.',
            'Give the builder the path you want the gadget to read. The secret lives at <code>/var/secret/flag.txt</code>.',
            'The lab writes a real <code>.phar</code> whose metadata is your <code>PharGadget</code>, then runs <code>file_exists("phar://.../test.txt")</code> — the file op alone kicks off metadata deserialization and fires <code>__wakeup()</code>.',
            'Just enter <code>/var/secret/flag.txt</code> as the gadget target and submit — the crafted phar + <code>phar://</code> file op does the rest. (PHP 8 removed the implicit auto-deserialization; this lab reproduces the classic behaviour.)',
        ],
        9 => [
            'This is an RCE POP chain: the destructor doesn\'t just read a file — it runs a shell command. Outer <code>Report::__destruct()</code> calls <code>$this->engine->run()</code>; inner <code>CommandRunner::run()</code> executes <code>shell_exec($this->cmd)</code>.',
            'You control <code>cmd</code>. To capture the flag, run a command that prints the secret file: <code>cat /var/secret/flag.txt</code>.',
            'Nest a <code>CommandRunner</code> (13 bytes) inside the <code>engine</code> property of a <code>Report</code> (6 bytes). The command string <code>cat /var/secret/flag.txt</code> is 24 bytes.',
            'Remember: nested objects carry no trailing semicolon. The inner object is the raw value of the <code>engine</code> property.',
            'Working payload: <code>O:6:"Report":1:{s:6:"engine";O:13:"CommandRunner":1:{s:3:"cmd";s:24:"cat /var/secret/flag.txt";}}</code>',
        ],
        10 => [
            'Two layers guard this endpoint. Layer 1: an HMAC signature. The token is <code>base64(serialized)|signature</code> and the server checks the signature with a secret key you don\'t have.',
            'Read the verification code carefully: the signature is only enforced <em>when it is non-empty</em> (<code>if ($sig !== "" &amp;&amp; !hash_equals(...))</code>). Send an <strong>empty</strong> signature and the whole check is skipped.',
            'Layer 2: after decoding, a WAF blocks payloads whose bytes match <code>/system|exec|passthru|shell|popen|proc_open/i</code>. So an RCE gadget name is out — use a quiet <em>file-read</em> gadget instead.',
            'The provided gadget is <code>AuditTrail</code> (10 bytes); its <code>__destruct()</code> reads <code>$this->file</code>. None of its names hit the WAF blacklist.',
            'Build <code>O:10:"AuditTrail":1:{s:4:"file";s:20:"/var/secret/flag.txt";}</code>, base64 it, and submit as <code>&lt;base64&gt;|</code> (trailing pipe, empty signature). The builder below can base64-encode it for you.',
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
 * Renders a small client-side PHP-serialization "payload builder" so learners
 * can see the O:len:"Class":count:{...} format and compute byte lengths.
 * Rendered once per page (static guard).
 */
function render_payload_builder(): string {
    static $rendered = false;
    if ($rendered) return '';
    $rendered = true;
    ob_start();
    ?>
    <div class="hints" id="poi_builder">
        <h3>Payload Builder &mdash; PHP serialize() format</h3>
        <div style="padding: 0.85rem 1rem; display:flex; flex-direction:column; gap:0.6rem;">
            <p style="font-size:0.8rem; color:var(--text-muted); line-height:1.6; margin:0;">
                An object serializes as <code>O:&lt;classNameByteLen&gt;:"Class":&lt;propCount&gt;:{ props }</code>.
                A string is <code>s:&lt;byteLen&gt;:"value";</code>, an int <code>i:&lt;n&gt;;</code>, a boolean <code>b:0;</code>/<code>b:1;</code>.
                Nested objects are pasted as-is (type <em>raw</em>, no trailing <code>;</code>). Byte lengths matter &mdash; this tool computes them for you.
            </p>
            <div class="form-group" style="margin:0;">
                <label class="form-label">Class name</label>
                <input type="text" id="pb_class" class="form-control" placeholder="Account" value="Account" autocomplete="off" spellcheck="false">
            </div>
            <div id="pb_rows" style="display:flex; flex-direction:column; gap:0.4rem;"></div>
            <div style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                <button type="button" class="btn btn-secondary btn-sm" id="pb_add">+ Add property</button>
                <button type="button" class="btn btn-primary btn-sm" id="pb_build">Serialize</button>
                <button type="button" class="btn btn-secondary btn-sm" id="pb_b64">Serialize + base64 (for L10)</button>
            </div>
            <label class="form-label" style="margin:0;">Output</label>
            <div class="output-box" id="pb_out" style="min-height:2.4rem;"></div>
        </div>
    </div>
    <script>
    (function(){
        const enc = new TextEncoder();
        const blen = s => enc.encode(s).length;
        const rows = document.getElementById('pb_rows');
        function addRow(name, type, val){
            const wrap = document.createElement('div');
            wrap.className = 'pb-row';
            wrap.style = 'display:flex; gap:0.4rem; flex-wrap:wrap; align-items:center;';
            wrap.innerHTML =
                '<input class="form-control pb-name" style="flex:1; min-width:110px;" placeholder="propName" value="'+(name||'')+'">'+
                '<select class="form-control pb-type" style="max-width:110px;">'+
                    '<option value="string">string</option>'+
                    '<option value="int">int</option>'+
                    '<option value="bool">bool</option>'+
                    '<option value="raw">raw/object</option>'+
                '</select>'+
                '<input class="form-control pb-val" style="flex:2; min-width:140px;" placeholder="value" value="'+(val||'')+'">'+
                '<button type="button" class="btn btn-secondary btn-sm pb-del">&times;</button>';
            rows.appendChild(wrap);
            if (type) wrap.querySelector('.pb-type').value = type;
            wrap.querySelector('.pb-del').addEventListener('click', ()=>wrap.remove());
        }
        function serVal(type, val){
            if (type === 'int')  return 'i:'+parseInt(val||'0',10)+';';
            if (type === 'bool') return 'b:'+((val==='1'||val==='true'||val===true)?'1':'0')+';';
            if (type === 'raw')  return val; // nested object, verbatim, no trailing ;
            return 's:'+blen(val)+':"'+val+'";';
        }
        function build(){
            const cls = document.getElementById('pb_class').value;
            const rws = [...rows.querySelectorAll('.pb-row')];
            let props = '';
            rws.forEach(r=>{
                const name = r.querySelector('.pb-name').value;
                const type = r.querySelector('.pb-type').value;
                const val  = r.querySelector('.pb-val').value;
                props += 's:'+blen(name)+':"'+name+'";'+serVal(type,val);
            });
            return 'O:'+blen(cls)+':"'+cls+'":'+rws.length+':{'+props+'}';
        }
        document.getElementById('pb_add').addEventListener('click', ()=>addRow('', 'string', ''));
        document.getElementById('pb_build').addEventListener('click', ()=>{
            document.getElementById('pb_out').textContent = build();
        });
        document.getElementById('pb_b64').addEventListener('click', ()=>{
            const s = build();
            document.getElementById('pb_out').textContent = btoa(unescape(encodeURIComponent(s)))+'|';
        });
        // seed with a sample
        addRow('username', 'string', 'guest');
        addRow('isAdmin', 'bool', '1');
    })();
    </script>
    <?php
    return ob_get_clean();
}

/**
 * Shared per-level <style> block. The suite's styles.css defines the panels,
 * source-code, hints and buttons; these few extra classes (level header,
 * difficulty badges, annotations, small buttons) reuse the same design tokens
 * so every level matches the rest of the Hackin Lab suite.
 */
function render_level_styles(): string {
    return <<<CSS
    <style>
        .header-title { font-size: 1.02rem; font-weight: 700; color: var(--white); }
        .submit-link { padding: 0.35rem 0.85rem; border-radius: 5px; text-decoration: none; font-size: 0.8rem; font-weight: 600; color: var(--bg); background: var(--white); border: 1px solid var(--white); }
        .level-header { display: flex; align-items: center; gap: 0.85rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
        .level-header h1 { font-size: 1.4rem; font-weight: 800; color: var(--white); letter-spacing: -0.01em; }
        .level-badge { font-size: 0.72rem; font-weight: 700; color: var(--text-faint); background: var(--surface3); border: 1px solid var(--border); padding: 3px 9px; border-radius: 3px; letter-spacing: 0.08em; text-transform: uppercase; }
        .difficulty-badge { font-size: 0.66rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; padding: 3px 9px; border-radius: 3px; border: 1px solid; }
        .difficulty-easy    { color: #d0d0d0; border-color: #3a3a3a; background: #141414; }
        .difficulty-medium  { color: #b0b0b0; border-color: #3a3a3a; background: #121212; }
        .difficulty-hard    { color: #909090; border-color: #2a2a2a; background: #0e0e0e; }
        .difficulty-expert  { color: var(--white); border-color: var(--border-hi); background: var(--surface3); }
        .vuln-annotation { margin: 0; padding: 0.85rem 1rem; font-size: 0.82rem; color: var(--text-muted); line-height: 1.65; border-top: 1px solid var(--border); background: var(--surface2); }
        .vuln-annotation strong { color: var(--text); }
        .challenge-panel .scenario:first-of-type { margin-top: 0; }
        .challenge-panel form, .challenge-panel .scenario, .challenge-panel .message, .challenge-panel .flag-display, .challenge-panel .output-section { margin-left: 1rem; margin-right: 1rem; }
        .output-section { margin-bottom: 1rem; }
        .output-section h4 { font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin: 0.75rem 0 0.4rem; }
        .flag-display h3 { color: var(--white); font-size: 0.95rem; margin-bottom: 0.35rem; padding: 0; border: 0; background: none; text-transform: none; letter-spacing: 0; }
        .flag-display p { color: var(--text-muted); font-size: 0.8rem; font-weight: 400; }
        .flag-display code { color: var(--white); background: var(--surface2); border: 1px solid var(--border-hi); }
        .btn-secondary { background: var(--surface2); color: var(--text-muted); border-color: var(--border-mid); }
        .btn-secondary:hover { color: var(--text); border-color: var(--border-hi); }
        .btn-sm { padding: 0.3rem 0.7rem; font-size: 0.76rem; }
        .nav-center { margin: 0 auto; }
        .gadget-note { font-size: 0.75rem; color: var(--text-faint); margin-top: 0.5rem; padding: 0 1rem; }
    </style>
CSS;
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
    if (!empty($_COOKIE['poi_lab_progress'])) {
        $decoded = json_decode($_COOKIE['poi_lab_progress'], true);
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
            setcookie('poi_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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
