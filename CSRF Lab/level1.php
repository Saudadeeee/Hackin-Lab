<?php
require_once __DIR__ . '/helpers.php';

$levelId = 1;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// change_email.php  (level 1)</span>
<span class="php-comment">// The admin is authenticated by the session cookie, which the browser</span>
<span class="php-comment">// attaches automatically to every request to this origin.</span>

<span class="php-variable">$email</span> = <span class="php-variable">$_GET</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>;          <span class="php-comment">// attacker-controlled</span>

<span class="php-comment">// No anti-CSRF token. No POST requirement. No checks at all.</span>
<span class="vuln-line"><span class="php-function">change_admin_email</span>(<span class="php-variable">$email</span>);            <span class="php-comment">// state change on any authenticated GET</span></span>
SRC;

$scaffold = "<!-- Target: change_email.php  |  Method: GET  |  Protection: none -->\n<!-- Make the admin's browser hit this URL automatically, then Deliver. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'No-Token GET State Change',
    'difficulty'    => 'Easy',
    'endpoint'      => 'change_email.php',
    'method_label'  => 'GET',
    'defense_label' => 'None',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; A sensitive state change is exposed over <code>GET</code> with no anti-CSRF token. Because the admin is logged in, the session cookie is sent automatically — a single <code>&lt;img&gt;</code> tag on any page forces the change.',
    'scenario_html' => '<p>The corporate admin panel lets the admin change the account email at <code>change_email.php</code>. You are the attacker: you cannot log in, but you can get the admin to open a page you control.</p><p>Craft a PoC that makes the admin\'s browser issue the request, then click <strong>Deliver to victim</strong>. The bot performs it with the admin session attached.</p>',
    'console_rows'  => [
        'Admin account email' => $state['admin_email'],
        'Attacker goal'       => 'change it to ' . CSRF_ATTACKER_EMAIL,
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 0,
    'next'          => 2,
]);
