<?php
/**
 * Open Redirect Lab - Helper Functions
 *
 * The redirect "engine" NEVER issues a live cross-site redirect. Instead it models
 * exactly how a browser would resolve the value each vulnerable level would hand to
 * `header("Location: ...")` (or to an <a href>/location assignment), computes the
 * EFFECTIVE destination host, and reports where the victim would have been sent.
 */

const REDIRECT_TRUSTED_HOST  = 'example-bank.local';
const REDIRECT_ATTACKER_HOST = 'evil.attacker.example';

/**
 * Returns the flag string for a given level ID.
 */
function get_flag_for_level(int $levelId): string {
    $flags = [
        1  => 'FLAG{redirect_basic}',
        2  => 'FLAG{redirect_protocol_relative}',
        3  => 'FLAG{redirect_prefix_bypass}',
        4  => 'FLAG{redirect_substring_bypass}',
        5  => 'FLAG{redirect_backslash}',
        6  => 'FLAG{redirect_userinfo}',
        7  => 'FLAG{redirect_encoding}',
        8  => 'FLAG{redirect_scheme}',
        9  => 'FLAG{redirect_crlf}',
        10 => 'FLAG{redirect_waf_bypass}',
    ];
    return $flags[$levelId] ?? '';
}

/**
 * Returns an array of 5 progressive hints for each level.
 */
function get_level_hints(int $levelId): array {
    $hints = [
        1 => [
            'The page reads the <code>next</code> parameter and hands it straight to <code>header("Location: ...")</code> with <strong>no validation at all</strong>.',
            'Because nothing checks the destination, you can steer the victim to any site you control.',
            'A bare hostname like <code>evil.attacker.example</code> is treated as a same-site <em>path</em>. You need a value the browser reads as an absolute destination.',
            'Supply a full absolute URL (with a scheme) or a protocol-relative URL so the browser leaves the current origin.',
            'Working payloads: <code>?next=https://evil.attacker.example</code> &nbsp;|&nbsp; <code>?next=//evil.attacker.example</code>',
        ],
        2 => [
            'The filter only accepts values where <code>str_starts_with($next, \'/\')</code> — the developer assumes a leading slash means "a path on our own site".',
            'Think about which <em>other</em> URL form also begins with a slash but is not a same-site path.',
            'A URL beginning with <code>//</code> is <strong>protocol-relative</strong>: the browser keeps the current scheme but treats the text after <code>//</code> as a brand-new host.',
            '<code>//evil.attacker.example</code> passes the starts-with-<code>/</code> check yet navigates to <code>evil.attacker.example</code>.',
            'Working payloads: <code>?next=//evil.attacker.example</code> &nbsp;|&nbsp; <code>?next=//evil.attacker.example/login</code>',
        ],
        3 => [
            'The check parses the host with <code>parse_url()</code> and then calls <code>str_starts_with($host, \'example-bank.local\')</code>.',
            'A prefix match on the host is not an equality match — many hostnames <em>begin</em> with those exact characters.',
            'Make the trusted name the leading label of a domain you actually control.',
            '<code>example-bank.local.evil.attacker.example</code> starts with <code>example-bank.local</code>, but its real registrable domain is <code>evil.attacker.example</code>.',
            'Working payload: <code>?next=https://example-bank.local.evil.attacker.example/login</code>',
        ],
        4 => [
            'This filter uses <code>str_contains($next, \'example-bank.local\')</code> — the trusted name may appear <em>anywhere</em> in the string.',
            'The substring does not have to be the host. It can live in the path, the query string, or the fragment.',
            'Put your attacker host first and drop the trusted name somewhere harmless, like the path.',
            '<code>https://evil.attacker.example/example-bank.local</code> contains the substring, yet the host the browser connects to is <code>evil.attacker.example</code>.',
            'Working payloads: <code>?next=https://evil.attacker.example/example-bank.local</code> &nbsp;|&nbsp; <code>?next=https://evil.attacker.example/?x=example-bank.local</code>',
        ],
        5 => [
            'This filter blocks <code>//</code> and <code>http(s):</code> but still allows a single leading <code>/</code>.',
            'Browsers normalise backslashes (<code>\\</code>) into forward slashes in URLs <em>before</em> resolving them.',
            'A value starting with <code>/\\</code> survives the "no <code>//</code>" check because it does not literally begin with two forward slashes.',
            'After the browser converts <code>\\</code> to <code>/</code>, <code>/\\evil.attacker.example</code> becomes <code>//evil.attacker.example</code> — protocol-relative.',
            'Working payloads: <code>?next=/\\evil.attacker.example</code> &nbsp;|&nbsp; <code>?next=/\\/evil.attacker.example</code>',
        ],
        6 => [
            'The host is extracted with a naive regex — everything between <code>://</code> and the next <code>/</code> — then checked with <code>str_starts_with(..., \'example-bank.local\')</code>.',
            'A URL authority can carry <strong>userinfo</strong> before an <code>@</code>: <code>scheme://user@host/</code>.',
            'Everything before the <code>@</code> is credentials, not the host — but a naive starts-with check reads it as the host.',
            '<code>https://example-bank.local@evil.attacker.example/</code> looks like it starts with the trusted name, yet the browser connects to <code>evil.attacker.example</code>.',
            'Working payload: <code>?next=https://example-bank.local@evil.attacker.example/</code>',
        ],
        7 => [
            'The filter rejects raw <code>//</code> and <code>http(s)://</code>, but the value is passed through <code>urldecode()</code> <em>after</em> the check.',
            'If you encode the dangerous characters, the check sees a harmless string; decoding restores the exploit.',
            'A forward slash <code>/</code> is <code>%2f</code> when URL-encoded &mdash; but PHP already percent-decodes the query string once when it populates <code>$_GET</code>, so a plain <code>%2f</code> reaches the filter as a real <code>/</code>. You need one <em>extra</em> layer so a literal <code>%2f</code> is still there when <code>urldecode()</code> runs.',
            'Send <code>%252f%252fevil.attacker.example</code>: the transport decode makes it <code>%2f%2fevil.attacker.example</code>, which does not start with <code>//</code>, and the extra <code>urldecode()</code> then makes that <code>//evil.attacker.example</code>.',
            'Working payload in the address bar: <code>?next=%252f%252fevil.attacker.example</code> (or <code>%252F%252F</code>). Typing it into the box on this page instead? The browser percent-encodes what you type, so there you only write <code>%2f%2fevil.attacker.example</code> &mdash; either way the filter must see <code>%2f%2f</code> and <code>urldecode()</code> must turn it into <code>//</code>.',
        ],
        8 => [
            'The check only asks "does this point at a foreign <em>host</em>?" using <code>parse_url()</code>\'s host — a value with no host slips past.',
            'Not every URL scheme has a host. Some schemes execute code or render inline content instead of navigating.',
            '<code>javascript:</code> and <code>data:</code> URLs have a <code>null</code> host, so the host allowlist never fires.',
            'When that value is dropped into an <code>href</code> or assigned to <code>location</code>, the browser runs it — the open redirect becomes script execution.',
            'Working payloads: <code>?next=javascript:alert(document.domain)</code> &nbsp;|&nbsp; <code>?next=data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</code>',
        ],
        9 => [
            'The value is <code>urldecode()</code>d and concatenated straight into <code>header("Location: ...")</code>.',
            'HTTP headers are separated by a carriage-return + line-feed (<code>CRLF</code>). Inject a CRLF and you can inject <em>new</em> headers.',
            '<code>%0d%0a</code> is the URL-encoding of CRLF. After it, you can begin your own header line.',
            'Inject a second <code>Location:</code> header (or any header) pointing at your host after the CRLF sequence.',
            'Working payload: <code>?next=/dashboard%0d%0aLocation:%20https://evil.attacker.example</code>',
        ],
        10 => [
            'Five layers block, in order: protocol-relative <code>//</code>, backslashes, dangerous schemes, percent-encoding, and a <code>parse_url()</code> host allowlist. Every earlier trick is covered — except one gap.',
            'The host allowlist trusts any value whose <code>parse_url()</code> host is <code>null</code>, assuming "no host = a safe relative path".',
            'PHP\'s <code>parse_url()</code> only recognises an authority after <code>//</code>. Browsers are far more lenient about how many slashes follow a scheme.',
            '<code>https:/evil.attacker.example</code> (a <em>single</em> slash) has a <code>null</code> host to <code>parse_url()</code>, but browsers normalise it to <code>https://evil.attacker.example</code>. It contains no <code>//</code>, no <code>\\</code>, no dangerous scheme, and no <code>%</code>.',
            'Working payload: <code>?next=https:/evil.attacker.example/login</code>',
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

/* =========================================================================
   Redirect engine — models browser URL resolution (never navigates)
   ========================================================================= */

/**
 * Extract the real host a browser would connect to from a URL authority,
 * stripping userinfo (everything up to the last '@') and any :port.
 */
function redirect_extract_host(string $authority): ?string {
    if ($authority === '') return null;
    $at = strrpos($authority, '@');
    if ($at !== false) {
        $authority = substr($authority, $at + 1);
    }
    $colon = strpos($authority, ':');
    if ($colon !== false) {
        $authority = substr($authority, 0, $colon);
    }
    $authority = strtolower(trim($authority));
    return $authority === '' ? null : $authority;
}

/**
 * True when a host belongs to the trusted bank domain (exact or a subdomain).
 */
function redirect_host_is_trusted(?string $host): bool {
    if ($host === null || $host === '') return false;
    $h = strtolower($host);
    return $h === REDIRECT_TRUSTED_HOST || str_ends_with($h, '.' . REDIRECT_TRUSTED_HOST);
}

/**
 * Model how a browser resolves a redirect/Location value relative to the lab
 * origin (https://example-bank.local). Returns the effective destination.
 *
 * @return array{kind:string,scheme:string,host:?string,authority:?string,url:string,offsite:bool,dangerous:bool}
 */
function redirect_browser_target(string $raw): array {
    $base = [
        'kind' => 'relative', 'scheme' => 'https', 'host' => REDIRECT_TRUSTED_HOST,
        'authority' => REDIRECT_TRUSTED_HOST, 'url' => 'https://' . REDIRECT_TRUSTED_HOST . '/',
        'offsite' => false, 'dangerous' => false,
    ];

    // Browsers strip Tab/LF/CR anywhere in the URL and trim leading/trailing controls + space.
    $s = str_replace(["\t", "\n", "\r"], '', $raw);
    $s = preg_replace('/^[\x00-\x20]+|[\x00-\x20]+$/', '', $s);
    if ($s === '') {
        return $base;
    }

    // Non-navigational / code-executing schemes (no host).
    if (preg_match('#^(javascript|data|vbscript)\s*:#i', $s, $m)) {
        return [
            'kind' => 'scheme', 'scheme' => strtolower($m[1]), 'host' => null, 'authority' => null,
            'url' => $s, 'offsite' => true, 'dangerous' => true,
        ];
    }

    // For special schemes browsers convert backslashes to forward slashes.
    $norm = str_replace('\\', '/', $s);

    // Absolute URL: scheme followed by one-or-more slashes, then an authority.
    if (preg_match('#^([a-zA-Z][a-zA-Z0-9+.\-]*):/+(.*)$#s', $norm, $m)) {
        $scheme = strtolower($m[1]);
        [$authority, $tail] = redirect_split_authority($m[2]);
        $host = redirect_extract_host($authority);
        if ($host === null) {
            return $base;
        }
        return [
            'kind' => 'absolute', 'scheme' => $scheme, 'host' => $host, 'authority' => $authority,
            'url' => $scheme . '://' . $authority . $tail,
            'offsite' => !redirect_host_is_trusted($host), 'dangerous' => false,
        ];
    }

    // Protocol-relative: two-or-more leading slashes then an authority.
    if (preg_match('#^//+(.*)$#s', $norm, $m)) {
        [$authority, $tail] = redirect_split_authority($m[1]);
        $host = redirect_extract_host($authority);
        if ($host === null) {
            return $base;
        }
        return [
            'kind' => 'protocol-relative', 'scheme' => 'https', 'host' => $host, 'authority' => $authority,
            'url' => 'https://' . $authority . $tail,
            'offsite' => !redirect_host_is_trusted($host), 'dangerous' => false,
        ];
    }

    // Absolute path or relative reference — stays on the same origin.
    $path = ($norm !== '' && $norm[0] === '/') ? $norm : '/' . $norm;
    return [
        'kind' => 'relative', 'scheme' => 'https', 'host' => REDIRECT_TRUSTED_HOST, 'authority' => REDIRECT_TRUSTED_HOST,
        'url' => 'https://' . REDIRECT_TRUSTED_HOST . $path,
        'offsite' => false, 'dangerous' => false,
    ];
}

/**
 * Split "authority[/path?query#frag]" into [authority, tail].
 */
function redirect_split_authority(string $rest): array {
    if (preg_match('/^([^\/?#]*)(.*)$/s', $rest, $m)) {
        return [$m[1], $m[2]];
    }
    return [$rest, ''];
}

/**
 * The REAL vulnerable server-side validation for each level.
 * Returns whether the redirect would be allowed, plus the string that would
 * actually be handed to the browser (after any level-specific decoding).
 *
 * @return array{allowed:bool,target:string,reason:string}
 */
function redirect_level_filter(int $level, string $input): array {
    $trusted = REDIRECT_TRUSTED_HOST;

    switch ($level) {
        case 1:
            return ['allowed' => true, 'target' => $input,
                'reason' => 'No validation is performed — the value is redirected exactly as supplied.'];

        case 2: {
            $ok = str_starts_with($input, '/');
            return ['allowed' => $ok, 'target' => $input,
                'reason' => $ok ? 'Value begins with "/", so it is accepted as a site-relative path.'
                                : 'Rejected: value does not begin with "/".'];
        }

        case 3: {
            $host = parse_url($input, PHP_URL_HOST) ?? '';
            $ok = $host !== '' && str_starts_with($host, $trusted);
            return ['allowed' => $ok, 'target' => $input,
                'reason' => $ok ? "parse_url() host \"$host\" starts with \"$trusted\"."
                                : "Rejected: parse_url() host \"$host\" does not start with \"$trusted\"."];
        }

        case 4: {
            $ok = str_contains($input, $trusted);
            return ['allowed' => $ok, 'target' => $input,
                'reason' => $ok ? "Value contains the substring \"$trusted\"."
                                : "Rejected: value does not contain \"$trusted\"."];
        }

        case 5: {
            $blocked = str_starts_with($input, '//') || (bool)preg_match('#^https?:#i', $input);
            $ok = !$blocked && str_starts_with($input, '/');
            $reason = $blocked
                ? 'Rejected: value starts with "//" or an "http(s):" scheme.'
                : ($ok ? 'Value starts with a single "/", accepted as a site-relative path.'
                       : 'Rejected: value is not a site-relative path.');
            return ['allowed' => $ok, 'target' => $input, 'reason' => $reason];
        }

        case 6: {
            $authority = '';
            if (preg_match('#^https?://([^/]+)#i', $input, $m)) {
                $authority = $m[1];
            }
            $ok = $authority !== '' && str_starts_with($authority, $trusted);
            return ['allowed' => $ok, 'target' => $input,
                'reason' => $ok ? "Extracted authority \"$authority\" starts with \"$trusted\"."
                                : ($authority === '' ? 'Rejected: value is not an http(s):// URL.'
                                                     : "Rejected: extracted authority \"$authority\" does not start with \"$trusted\".")];
        }

        case 7: {
            $blocked = str_starts_with($input, '//') || (bool)preg_match('#^https?://#i', $input);
            $target = urldecode($input);
            return ['allowed' => !$blocked, 'target' => $target,
                'reason' => $blocked ? 'Rejected: raw value starts with "//" or "http(s)://".'
                                     : 'Accepted (the raw value looks relative); it is then urldecode()d before the redirect.'];
        }

        case 8: {
            $host = parse_url($input, PHP_URL_HOST);
            $ok = ($host === null || $host === $trusted);
            return ['allowed' => $ok, 'target' => $input,
                'reason' => $ok ? 'Accepted: parse_url() reports no foreign host.'
                                : "Rejected: foreign host \"$host\"."];
        }

        case 9: {
            $host = parse_url($input, PHP_URL_HOST);
            $target = urldecode($input);
            $ok = ($host === null);
            return ['allowed' => $ok, 'target' => $target,
                'reason' => $ok ? 'Accepted: parse_url() reports no host, so it looks relative; the value is urldecode()d into the header.'
                                : "Rejected: parse_url() host \"$host\"."];
        }

        case 10: {
            $s = trim($input);
            if (str_starts_with($s, '//')) {
                return ['allowed' => false, 'target' => $input, 'reason' => 'Layer 1 blocked: value starts with "//".'];
            }
            if (str_contains($s, '\\')) {
                return ['allowed' => false, 'target' => $input, 'reason' => 'Layer 2 blocked: value contains a backslash.'];
            }
            if (preg_match('/^(javascript|data|vbscript):/i', $s)) {
                return ['allowed' => false, 'target' => $input, 'reason' => 'Layer 3 blocked: dangerous scheme.'];
            }
            if (str_contains($s, '%')) {
                return ['allowed' => false, 'target' => $input, 'reason' => 'Layer 4 blocked: value contains "%".'];
            }
            $host = parse_url($s, PHP_URL_HOST);
            $ok = ($host === null || $host === $trusted || str_ends_with((string)$host, '.' . $trusted));
            return ['allowed' => $ok, 'target' => $s,
                'reason' => $ok ? 'Layer 5 passed: parse_url() host is null or within the bank domain.'
                                : "Layer 5 blocked: parse_url() host \"$host\" is outside the allowlist."];
        }

        default:
            return ['allowed' => false, 'target' => $input, 'reason' => 'Unknown level.'];
    }
}

/**
 * Run a level's real vulnerable validation against the input, then compute the
 * effective destination a browser would navigate to. Awards the flag (captured)
 * when the redirect resolves off the allowlist / to a dangerous scheme / via a
 * CRLF-injected header — WITHOUT ever issuing the live redirect.
 *
 * @return array{submitted:bool,allowed:bool,reason:string,target:string,
 *               effective:?array,captured:bool,kind:string,injected:?array,message:string}
 */
function verify_redirect(int $level, string $input): array {
    $res = [
        'submitted' => ($input !== ''),
        'allowed'   => false,
        'reason'    => '',
        'target'    => '',
        'effective' => null,
        'captured'  => false,
        'kind'      => 'blocked',
        'injected'  => null,
        'message'   => '',
    ];

    if ($input === '') {
        return $res;
    }

    $filter = redirect_level_filter($level, $input);
    $res['allowed'] = $filter['allowed'];
    $res['reason']  = $filter['reason'];
    $res['target']  = $filter['target'];

    if (!$filter['allowed']) {
        $res['kind']    = 'blocked';
        $res['message'] = 'The redirect filter rejected this value — no redirect would be issued.';
        return $res;
    }

    // Level 9: CRLF header injection has its own semantics.
    if ($level === 9) {
        $decoded = $filter['target'];
        if (preg_match('/[\r\n]/', $decoded)) {
            $lines    = preg_split('/\r\n|\r|\n/', $decoded);
            $injected = array_values(array_filter(array_slice($lines, 1), fn($l) => $l !== ''));
            $res['injected'] = $injected;

            if (!empty($injected)) {
                $res['captured'] = true;
                $res['kind']     = 'crlf';
                $loc = null;
                foreach ($injected as $line) {
                    if (preg_match('/^\s*Location\s*:\s*(.+)$/i', $line, $m)) {
                        $loc = trim($m[1]);
                        break;
                    }
                }
                if ($loc !== null) {
                    $res['effective'] = redirect_browser_target($loc);
                    $res['message']   = 'CRLF injection succeeded — you injected ' . count($injected)
                        . ' header line(s), including a Location header the victim would follow.';
                } else {
                    $res['message'] = 'CRLF injection succeeded — you injected ' . count($injected)
                        . ' arbitrary response header(s).';
                }
                return $res;
            }
        }
        $res['effective'] = redirect_browser_target($filter['target']);
        $res['kind']      = 'safe';
        $res['message']   = 'Redirect allowed to a same-site path — no header injection.';
        return $res;
    }

    // All other levels: resolve the effective destination the browser would load.
    $eff = redirect_browser_target($filter['target']);
    $res['effective'] = $eff;

    if ($eff['dangerous']) {
        $res['captured'] = true;
        $res['kind']     = 'dangerous_scheme';
        $res['message']  = 'Dangerous "' . $eff['scheme'] . ':" scheme accepted — the browser would execute this instead of navigating.';
    } elseif ($eff['offsite']) {
        $res['captured'] = true;
        $res['kind']     = 'offsite';
        $res['message']  = 'The redirect resolves to an off-allowlist host: ' . $eff['host'] . '.';
    } else {
        $res['kind']    = 'safe';
        $res['message'] = 'Redirect allowed to the trusted destination (' . $eff['host'] . ') — no bypass.';
    }

    return $res;
}

/**
 * Render the redirect-engine result panel (verdict + effective destination).
 * Composed entirely from existing lab classes so it matches the suite theme.
 * Renders the destination as TEXT — it never navigates.
 */
function render_redirect_result(array $vr): string {
    if (empty($vr['submitted'])) return '';
    $eff = $vr['effective'] ?? null;
    ob_start();
    ?>
    <div class="xss-output-section" style="margin-top:0.85rem;">
        <h4>Redirect Engine Trace:</h4>
        <div class="output-box" style="white-space:normal;">
            <div>
                <span style="color:var(--text-muted);">Filter verdict:</span>
                <?php if ($vr['allowed']): ?>
                    <strong style="color:#7fa06d;">ALLOWED</strong>
                <?php else: ?>
                    <strong style="color:#b5766e;">BLOCKED</strong>
                <?php endif; ?>
            </div>
            <div style="margin-top:0.35rem; color:var(--text-muted);"><?= htmlspecialchars($vr['reason']) ?></div>

            <?php if ($vr['allowed'] && $vr['kind'] === 'crlf'): ?>
                <div style="margin-top:0.65rem; color:var(--text-muted);">Injected response header(s):</div>
                <?php foreach (($vr['injected'] ?? []) as $h): ?>
                    <div><code style="color:#cfa65c; word-break:break-all;"><?= htmlspecialchars($h) ?></code></div>
                <?php endforeach; ?>
                <?php if ($eff): ?>
                    <div style="margin-top:0.5rem; color:var(--text-muted);">Injected <code>Location</code> &rarr; browser would load:</div>
                    <div><code style="color:#b5766e; word-break:break-all;"><?= htmlspecialchars($eff['url']) ?></code></div>
                <?php endif; ?>

            <?php elseif ($vr['allowed'] && $eff): ?>
                <div style="margin-top:0.65rem; color:var(--text-muted);">Effective destination the browser would load:</div>
                <div>
                    <code style="color:<?= ($eff['offsite'] || $eff['dangerous']) ? '#b5766e' : '#7fa06d' ?>; word-break:break-all;"><?= htmlspecialchars($eff['url']) ?></code>
                </div>
                <div style="margin-top:0.45rem;">
                    <span style="color:var(--text-muted);">Resolved host:</span>
                    <?php if ($eff['dangerous']): ?>
                        <code style="color:#b5766e;"><?= htmlspecialchars($eff['scheme']) ?>: (no host &mdash; code execution)</code>
                    <?php else: ?>
                        <code style="color:<?= $eff['offsite'] ? '#b5766e' : '#7fa06d' ?>;"><?= htmlspecialchars((string)$eff['host']) ?></code>
                        <span style="color:var(--text-faint); font-size:0.75rem;">
                            <?= $eff['offsite'] ? '(off-allowlist / attacker-controlled)' : '(trusted)' ?>
                        </span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
        <p class="xss-sandbox-note" style="font-size:0.78rem; color:var(--text-faint); margin-top:0.4rem;">
            This lab <strong>computes</strong> where the browser would navigate and renders it as text. It never issues
            the live cross-site redirect, so nothing actually leaves this page.
        </p>
    </div>
    <?php
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
    if (!empty($_COOKIE['redirect_lab_progress'])) {
        $decoded = json_decode($_COOKIE['redirect_lab_progress'], true);
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
            setcookie('redirect_lab_progress', json_encode($completed), time() + 86400 * 30, '/');
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
