<?php
require_once __DIR__ . '/helpers.php';

$levelId = 8;
$p     = csrf_level_prepare($levelId);
$state = $p['state'];

$source = <<<'SRC'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// change_email.php  (level 8)</span>
<span class="php-variable">$ref</span> = <span class="php-variable">$_SERVER</span>[<span class="php-string">'HTTP_REFERER'</span>] ?? <span class="php-string">''</span>;

<span class="php-comment">// Naive Referer check — but when the header is ABSENT it "fails open".</span>
<span class="vuln-line"><span class="php-keyword">if</span> (<span class="php-variable">$ref</span> !== <span class="php-string">''</span> &amp;&amp; <span class="php-function">parse_url</span>(<span class="php-variable">$ref</span>, <span class="php-keyword">PHP_URL_HOST</span>) !== <span class="php-string">'csrf-lab.local'</span>) {</span>
    <span class="php-function">http_response_code</span>(<span class="php-string">403</span>); <span class="php-keyword">exit</span>;      <span class="php-comment">// only blocks a PRESENT cross-site Referer</span>
}
<span class="php-function">change_admin_email</span>(<span class="php-variable">$_POST</span>[<span class="php-string">'email'</span>] ?? <span class="php-string">''</span>);   <span class="php-comment">// state change</span>
SRC;

$scaffold = "<!-- Target: change_email.php  |  Method: POST  |  Protection: Referer check (fails open when absent) -->\n<!-- Suppress the Referer header, then submit the form. -->\n";

csrf_render_level([
    'id'            => $levelId,
    'title'         => 'Referer Check Bypass',
    'difficulty'    => 'Hard',
    'endpoint'      => 'change_email.php',
    'method_label'  => 'POST',
    'defense_label' => 'Referer check',
    'samesite'      => 'None',
    'source_html'   => $source,
    'vuln_annotation' => '<strong>Vulnerability:</strong>&nbsp; The Referer check only rejects a request whose Referer is <em>present and cross-site</em>. When the header is absent it falls through to the state change. An attacker page can simply suppress the Referer with a no-referrer policy.',
    'scenario_html' => '<p>This endpoint blocks forged POSTs by inspecting the <code>Referer</code> header — a common but fragile defense.</p><p>Make the admin\'s browser send the POST with no Referer, and deliver it.</p>',
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
    'prev'          => 7,
    'next'          => 9,
]);
