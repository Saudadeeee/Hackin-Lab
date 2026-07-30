<?php
require_once __DIR__ . '/helpers.php';

$levelId = 7;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// api_update.php  (level 7)</span>
<span class="php-comment">// "JSON API" — assumed safe because a JSON request needs a CORS preflight.</span>

<span class="vuln-line"><span class="php-variable">$data</span> = <span class="php-function">json_decode</span>(<span class="php-function">file_get_contents</span>(<span class="php-string">'php://input'</span>), <span class="php-keyword">true</span>);  <span class="php-comment">// reads RAW body</span></span>

<span class="php-comment">// No token, and no Content-Type check. A simple text/plain body that</span>
<span class="php-comment">// happens to be JSON is sent cross-site with NO preflight.</span>
<span class="php-function">change_admin_email</span>(<span class="php-variable">$data</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change</span>
SRC;

$scaffold = "<!-- Target: api_update.php  |  Method: POST  |  Body: JSON  |  Protection: assumed CORS preflight -->\n<!-- application/json triggers a preflight (blocked). Use a SIMPLE content type. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'JSON Endpoint via text/plain',
    'difficulty'    => 'Hard',
    'endpoint'      => 'api_update.php',
    'method_label'  => 'POST (JSON)',
    'defense_label' => 'Assumed CORS preflight',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; The endpoint <code>json_decode()</code>s the raw body and assumes JSON requests are safe because they trigger a CORS preflight. But <code>Content-Type: text/plain</code> is a <em>simple request</em> — no preflight — so a text/plain body that is valid JSON reaches the handler.',
    'scenario_html' => '<p>The profile API reads a JSON body and has no token. It relies on the belief that only same-origin JavaScript can POST JSON.</p><p>Send a cross-site request with a simple content type carrying a JSON body, and deliver it.</p>',
    'console_rows'  => [
        'Admin account email' => $state['admin_email'],
        'Attacker goal'       => 'change email to ' . CSRF_ATTACKER_EMAIL,
    ],
    'scaffold'      => $scaffold,
    'result'        => $p['result'],
    'solved'        => $p['solved'],
    'flag'          => $p['flag'],
    'hints'         => $p['hints'],
    'flag_form'     => $p['flag_form'],
    'prev'          => 6,
    'next'          => 8,
]);
