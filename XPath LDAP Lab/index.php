<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    xl_lab(),
    xl_levels(),
    'XPath and LDAP filters are query languages, and both are usually assembled the way SQL used to be:
     by concatenating strings. Levels 1-5 build real XPath 1.0 expressions and evaluate them with
     <code>DOMXPath</code> against the XML directory shipped in <code>users.xml</code>. Levels 6-10 build real
     RFC 4515 filter strings and hand them to the parser and evaluator in <code>ldap.php</code>. Every page shows
     the code that runs, traces your input through it, prints the expression or the parse tree that resulted, and
     explains why the winning payload won.',
    '<strong>How to read these levels:</strong> the trace always ends with the thing the engine actually did &mdash;
     the node count for XPath, the parse tree for LDAP. A payload that fails is more informative than one that
     works, because the trace shows exactly which byte the parser choked on. Levels 3 and 9 are blind and ship a
     probe console so the lesson is the extraction strategy, not the typing.'
);
