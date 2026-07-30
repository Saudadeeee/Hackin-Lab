<?php
require_once __DIR__ . '/helpers.php';

$levelId = 10;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// transfer_owner.php  (level 10) — token + SameSite=Lax + Referer</span>
<span class="php-variable">$token</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'csrf_token'</span>] ?? <span class="php-string">''</span>;
<span class="php-variable">$ref</span>   = <span class="php-variable">$_SERVER</span>[<span class="php-string">'HTTP_REFERER'</span>] ?? <span class="php-string">''</span>;

<span class="php-keyword">if</span> (!<span class="php-function">preg_match</span>(<span class="php-string">'/^[a-f0-9]{32}$/i'</span>, <span class="php-variable">$token</span>)) { <span class="php-keyword">exit</span>; }         <span class="php-comment">// format only (L5 flaw)</span>
<span class="php-keyword">if</span> (<span class="php-variable">$ref</span> !== <span class="php-string">''</span> &amp;&amp; <span class="php-function">host</span>(<span class="php-variable">$ref</span>) !== <span class="php-string">'csrf-lab.local'</span>) { <span class="php-keyword">exit</span>; }   <span class="php-comment">// fails open (L8 flaw)</span>

<span class="php-comment">// Cookie is SameSite=Lax — yet this action is reachable over GET (L6 gap).</span>
<span class="vuln-line"><span class="php-function">transfer_ownership</span>(<span class="php-variable">$_GET</span>[<span class="php-string">'new_owner'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change via top-level GET</span></span>
SRC;

$scaffold = "<!-- Target: transfer_owner.php  |  Method: GET  |  Protection: token + SameSite=Lax + Referer -->\n<!-- Chain the three gaps: top-level GET nav (Lax), no-referrer (Referer), any 32-hex token (binding). -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Multi-Layer Defense Bypass',
    'difficulty'    => 'Expert',
    'endpoint'      => 'transfer_owner.php',
    'method_label'  => 'GET',
    'defense_label' => 'Token + SameSite + Referer',
    'samesite'      => 'Lax',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; Three defenses, each with the gap you already met: the token is format-only (not session-bound), SameSite=Lax still carries the cookie on top-level GET navigation, and the Referer check fails open when suppressed. Because the action is reachable over <code>GET</code>, one crafted navigation slips through all three.',
    'scenario_html' => '<p>The ownership-transfer endpoint stacks a CSRF token, a <code>SameSite=Lax</code> cookie, and a <code>Referer</code> check. Individually solid; together they still leave one uncovered path.</p><p>Combine everything you learned in levels 5, 6 and 8 into a single PoC and deliver it.</p>',
    'console_rows'  => [
        'Account owner' => $state['owner'],
        'Cookie policy' => 'admin_session; SameSite=Lax',
        'Attacker goal' => 'transfer ownership to ' . CSRF_TARGET_USER,
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 9,
    'next'          => 0,
]);
