<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

// --- Challenge logic ---
function decode_jwt(string $token): array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return [];
    // VULNERABLE: only decodes payload, NEVER verifies signature!
    $payload = json_decode(
        base64_decode(strtr($parts[1], '-_', '+/')),
        true
    );
    return $payload ?? [];
}

// Sample legitimate JWT for alice (role=user)
$sampleJwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.'
           . 'eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidXNlciIsImlkIjoxfQ.'
           . 'fake_signature_not_verified';

$token     = $_COOKIE['token'] ?? '';
$payload   = $token ? decode_jwt($token) : [];
$role      = $payload['role'] ?? 'guest';
$flagFound = ($role === 'admin');

$_flag_result = handle_inline_flag_submit(9);
html_open('Level 9 — JWT No Signature Verification');
render_page_header('Level 9 — JWT Without Signature Verification', 'Forging JWT Tokens to Escalate Privilege', 9);
?>

<div class="context-bar">
    <div>Cookie <code>token</code>: <span style="font-family:Consolas,monospace;font-size:0.78rem;"><?= $token ? htmlspecialchars(substr($token, 0, 60)) . '...' : '(not set)' ?></span></div>
    <div>Decoded Role: <span style="color:<?= $role === 'admin' ? 'var(--white)' : 'var(--text-muted)' ?>;font-weight:<?= $role === 'admin' ? '700' : '400' ?>;"><?= htmlspecialchars($role) ?></span></div>
</div>

<div class="challenge-layout">

    <!-- Source Code Panel -->
    <div class="code-panel">
        <h3>Vulnerable Source Code — level9.php</h3>
        <div class="source-code"><code><span class="php-keyword">&lt;?php</span>
<span class="php-keyword">function</span> <span class="php-function">decode_jwt</span>(<span class="php-keyword">string</span> <span class="php-variable">$token</span>): <span class="php-keyword">array</span> {
    <span class="php-variable">$parts</span> = <span class="php-function">explode</span>(<span class="php-string">'.'</span>, <span class="php-variable">$token</span>);
    <span class="php-keyword">if</span> (<span class="php-function">count</span>(<span class="php-variable">$parts</span>) !== <span class="php-string">3</span>) <span class="php-keyword">return</span> [];

    <span class="php-comment">// VULNERABLE: decodes payload, NEVER verifies signature!</span>
<span class="vuln-line">    <span class="php-variable">$payload</span> = <span class="php-function">json_decode</span>(
        <span class="php-function">base64_decode</span>(<span class="php-function">strtr</span>(<span class="php-variable">$parts</span>[<span class="php-string">1</span>], <span class="php-string">'-_'</span>, <span class="php-string">'+/'</span>)),
        <span class="php-keyword">true</span>
    );</span>
    <span class="php-keyword">return</span> <span class="php-variable">$payload</span> ?? [];
}

<span class="php-variable">$token</span>   = <span class="php-variable">$_COOKIE</span>[<span class="php-string">'token'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$payload</span> = <span class="php-function">decode_jwt</span>(<span class="php-variable">$token</span>);
<span class="php-variable">$role</span>    = <span class="php-variable">$payload</span>[<span class="php-string">'role'</span>] ?? <span class="php-string">'guest'</span>;

<span class="php-keyword">if</span> (<span class="php-variable">$role</span> === <span class="php-string">'admin'</span>) {
    <span class="php-comment">// Grant admin access — no signature check done!</span>
}
<span class="php-keyword">?&gt;</span></code></div>
        <div class="message info" style="margin-top:0.75rem;">
            <strong>Vulnerability:</strong> The server decodes the JWT payload with Base64 but never verifies
            the HMAC signature. The signature part (<code>parts[2]</code>) is completely ignored.
            A secure implementation would use <code>hash_hmac('sha256', ...)</code> to verify
            <code>header.payload</code> against the stored secret.
        </div>
    </div>

    <!-- Challenge Panel -->
    <div class="challenge-panel">
        <h3>JWT Forge Tool</h3>
        <div class="scenario">
            <strong>Scenario:</strong> The app uses JWT tokens stored in a <code>token</code> cookie.
            The server never validates the signature. Forge a token where <code>"role":"admin"</code>
            and set it as your cookie.
        </div>

        <?php if ($flagFound): ?>
        <div class="message success">JWT forged successfully! Admin role accepted without signature verification!</div>
        <div class="flag-display"><?= htmlspecialchars(get_flag_for_level(9)) ?></div>
        <?php else: ?>
        <div class="message info">
            Set your <code>token</code> cookie to a forged JWT with <code>"role":"admin"</code>
            in the payload, then refresh this page.
        </div>
        <?php endif; ?>

        <div style="margin-top:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text);margin-bottom:0.5rem;"><strong>Sample legitimate JWT (alice, role=user):</strong></p>
            <code style="display:block;font-size:0.75rem;color:#f1fa8c;word-break:break-all;margin-bottom:0.75rem;"><?= htmlspecialchars($sampleJwt) ?></code>

            <p style="font-size:0.82rem;color:var(--text-muted);margin-bottom:0.3rem;">JWT structure: <code>header.payload.signature</code></p>
            <table class="data-table" style="margin-bottom:0.75rem;">
                <thead><tr><th>Part</th><th>Base64 Decoded</th></tr></thead>
                <tbody>
                    <tr><td>Header</td><td><code>{"alg":"none","typ":"JWT"}</code></td></tr>
                    <tr><td>Payload</td><td><code>{"user":"alice","role":"user","id":1}</code></td></tr>
                    <tr><td>Signature</td><td><code>fake_signature_not_verified</code> <span style="color:var(--text-muted);">(ignored!)</span></td></tr>
                </tbody>
            </table>
        </div>

        <div style="margin-top:0.75rem;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:0.75rem 1rem;">
            <p style="font-size:0.85rem;color:var(--text);margin-bottom:0.5rem;"><strong>JWT Encoder/Decoder Tool:</strong></p>

            <div class="form-group">
                <label style="font-size:0.82rem;">Payload JSON (edit and encode)</label>
                <textarea id="jwtPayload" class="form-control" rows="3" style="font-family:Consolas,monospace;font-size:0.82rem;">{"user":"alice","role":"user","id":1}</textarea>
            </div>

            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem;">
                <button onclick="encodeAndSetJWT()" class="btn btn-primary" style="font-size:0.82rem;">
                    Encode &amp; Set Cookie
                </button>
                <button onclick="decodeCurrentToken()" class="btn" style="background:var(--surface2);color:var(--text);font-size:0.82rem;">
                    Decode Current Token
                </button>
                <button onclick="setAdminToken()" class="btn btn-outline" style="font-size:0.82rem;">
                    Auto-forge Admin Token
                </button>
                <button onclick="clearToken()" class="btn" style="font-size:0.82rem;border-color:var(--border-hi);">
                    Clear Cookie
                </button>
            </div>

            <div class="form-group">
                <label style="font-size:0.82rem;">Generated JWT Token</label>
                <textarea id="jwtOutput" class="form-control" rows="3" style="font-family:Consolas,monospace;font-size:0.75rem;word-break:break-all;" readonly></textarea>
            </div>
            <div id="jwtStatus" style="font-size:0.82rem;color:var(--text-muted);"></div>
        </div>
    </div>

</div>

<?= render_hint_section(get_level_hints(9)) ?>
<?= render_inline_flag_form(9, $_flag_result) ?>

<div class="navigation">
    <a href="level8.php" class="prev-link">&#8592; Level 8</a>
    <a href="index.php" class="nav-link">Lab Home</a>
    <a href="level10.php" class="next-link">Level 10 &rarr;</a>
</div>

<script>
// Base64url encode (RFC 4648)
function b64url(str) {
    return btoa(unescape(encodeURIComponent(str)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
// Base64url decode
function b64urlDecode(str) {
    try {
        return decodeURIComponent(escape(atob(str.replace(/-/g, '+').replace(/_/g, '/'))));
    } catch(e) { return str; }
}

function encodeAndSetJWT() {
    try {
        const header  = '{"alg":"none","typ":"JWT"}';
        const payload = document.getElementById('jwtPayload').value;
        JSON.parse(payload); // validate JSON
        const token = b64url(header) + '.' + b64url(payload) + '.forge_sig';
        document.getElementById('jwtOutput').value = token;
        document.cookie = 'token=' + encodeURIComponent(token) + '; path=/';
        document.getElementById('jwtStatus').innerHTML =
            '<span style="color:#d0d0d0;">Cookie set! <a href="level9.php" style="color:#ffffff;text-decoration:underline;">Reload page</a> to check role.</span>';
    } catch(e) {
        document.getElementById('jwtStatus').textContent = 'Invalid JSON in payload: ' + e.message;
    }
}

function decodeCurrentToken() {
    const raw = document.cookie.split(';').map(c => c.trim())
        .find(c => c.startsWith('token='));
    if (!raw) {
        document.getElementById('jwtStatus').textContent = 'No token cookie found.';
        return;
    }
    const token  = decodeURIComponent(raw.split('=').slice(1).join('='));
    const parts  = token.split('.');
    if (parts.length !== 3) {
        document.getElementById('jwtStatus').textContent = 'Not a valid JWT structure.';
        return;
    }
    try {
        const payload = JSON.parse(b64urlDecode(parts[1]));
        document.getElementById('jwtPayload').value = JSON.stringify(payload, null, 2);
        document.getElementById('jwtOutput').value  = token;
        document.getElementById('jwtStatus').innerHTML =
            'Decoded payload. Role: <strong style="color:' +
            (payload.role === 'admin' ? '#ffffff' : '#888888') + ';">' + payload.role + '</strong>';
    } catch(e) {
        document.getElementById('jwtStatus').textContent = 'Could not decode: ' + e.message;
    }
}

function setAdminToken() {
    const payload = '{"user":"alice","role":"admin","id":1}';
    document.getElementById('jwtPayload').value = payload;
    encodeAndSetJWT();
}

function clearToken() {
    document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    document.getElementById('jwtOutput').value = '';
    document.getElementById('jwtStatus').innerHTML =
        '<span style="color:#888888;">Cookie cleared. <a href="level9.php" style="color:#ffffff;text-decoration:underline;">Reload page.</a></span>';
}

// Auto-decode on page load if token exists
window.addEventListener('DOMContentLoaded', function() {
    const raw = document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith('token='));
    if (raw) decodeCurrentToken();
});
</script>

<?php html_close(); ?>
