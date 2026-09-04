<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    bp_lab(),
    bp_levels(),
    'Two policies decide what one origin may do to another. CORS decides who may <em>read</em> your responses;
     Content-Security-Policy decides what may <em>run</em> on your pages. Both are enforced by the browser and
     configured by the server, which means every bug in them is a bug in a string somebody wrote. Levels 1 to 5
     take an origin allowlist apart one comparison at a time. Levels 6 to 10 do the same to a CSP, from an
     allowlisted endpoint that hands out code to a loader that turns markup into a script URL.',
    '<strong>How the levels work:</strong> the CORS levels send a real request to <a href="api.php?level=1">api.php</a>
     with the Origin you supply and print the real response headers, so the flag is awarded for the headers the
     server actually emitted. The CSP levels send a real <code>Content-Security-Policy</code> header from
     <a href="render.php?level=6">render.php</a> and render your payload inside a frame, so your browser gives its
     own verdict; alongside it, <code>csp.php</code> evaluates the same policy string and shows which directive made
     the decision. Nothing is decided by matching a payload against a pattern.'
);
