<?php
$levelId    = 3;
$levelTitle = 'Content-Type (MIME) Spoofing';
$difficulty = 'Medium';

$scenario = <<<'HTML'
<p>This uploader trusts the <code>Content-Type</code> header and only accepts <code>image/png</code>.
The check happens before the file is stored under <code>uploads/level3/</code>.</p>
<p>The MIME header is set by the client. Forge it while uploading PHP, then read
<code>/var/secret/level3_flag.txt</code>.</p>
HTML;

$vulnNote = <<<'HTML'
<strong>Vulnerability:</strong>&nbsp; The <code>Content-Type</code> is attacker-supplied request metadata,
not derived from the file bytes. Claiming <code>image/png</code> while uploading a <code>.php</code> file
passes the check. Verify file type from the actual content, never the client header.
HTML;

$sourceCode = <<<'HTML'
<span class="php-keyword">&lt;?php</span>
<span class="php-comment">// level3.php — trusts the client-supplied Content-Type</span>
<span class="php-keyword">function</span> <span class="php-function">filter_level3</span>(<span class="php-keyword">array</span> <span class="php-variable">$u</span>): <span class="php-keyword">array</span> {
<span class="vuln-line">    <span class="php-keyword">if</span> (<span class="php-variable">$u</span>[<span class="php-string">'mime'</span>] !== <span class="php-string">'image/png'</span>) {          <span class="php-comment">// $_FILES['file']['type'] is forgeable</span></span>
        <span class="php-keyword">return</span> [<span class="php-keyword">false</span>, <span class="php-string">"Rejected: Content-Type must be image/png."</span>];
    }
    <span class="php-keyword">return</span> [<span class="php-keyword">true</span>, <span class="php-string">"Accepted: Content-Type is image/png."</span>];
}
<span class="php-comment">// The filename/extension is never checked -> shell.php with a forged MIME wins.</span>
HTML;

require __DIR__ . '/render_level.php';
