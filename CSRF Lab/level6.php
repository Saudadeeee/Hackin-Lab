<?php
require_once __DIR__ . '/helpers.php';

$levelId = 6;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// quick_email.php  (level 6)</span>
<span class="php-comment">// Session cookie is set with: SameSite=Lax</span>
<span class="php-comment">// The developer trusts SameSite=Lax and adds NO token.</span>

<span class="php-variable">$email</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>;          <span class="php-comment">// GET "quick action"</span>

<span class="php-comment">// SameSite=Lax STILL sends the cookie on top-level GET navigations.</span>
<span class="vuln-line"><span class="php-function">change_admin_email</span>(<span class="php-variable">$email</span>);            <span class="php-comment">// reachable via top-level GET nav</span></span>
SRC;

$scaffold = "<!-- Target: quick_email.php  |  Method: GET  |  Protection: SameSite=Lax cookie, no token -->\n<!-- A cross-site POST or <img> won't send the Lax cookie. -->\n<!-- Force a TOP-LEVEL GET navigation instead. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'SameSite=Lax Bypass',
    'difficulty'    => 'Medium',
    'endpoint'      => 'quick_email.php',
    'method_label'  => 'GET',
    'defense_label' => 'SameSite=Lax only',
    'samesite'      => 'Lax',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; SameSite=Lax is treated as a complete CSRF defense. It blocks cross-site POSTs and subresource loads, but <em>still</em> attaches the cookie to top-level GET navigations — and this state change is reachable via GET.',
    'scenario_html' => '<p>The admin_session cookie is <code>SameSite=Lax</code>, so the level 2 form CSRF and an <code>&lt;img&gt;</code> both fail here — the cookie is not sent.</p><p>Find the request type that Lax still trusts, and deliver it.</p>',
    'console_rows'  => [
        'Admin account email' => $state['admin_email'],
        'Cookie policy'       => 'admin_session; SameSite=Lax',
        'Attacker goal'       => 'change email to ' . CSRF_ATTACKER_EMAIL,
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 5,
    'next'          => 7,
]);
