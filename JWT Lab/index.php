<?php
require_once __DIR__ . '/helpers.php';

lk_index_page(
    jwtlab(),
    jwt_levels(),
    'A JSON Web Token is only as trustworthy as the code that checks it. These ten levels walk the standard
     verification flow one step at a time and break exactly one thing per level, from "the payload was never
     secret" to "two parsers read the same bytes differently". Each page shows the real verifier, traces your
     token through it, and explains why the winning payload won.',
    '<strong>Start here:</strong> the <a href="tools.php">JWT Workbench</a> decodes, edits, signs, cracks and
     generates keys locally, so no level is ever about base64 plumbing. Levels 4, 9 and 10 share a signing key on
     purpose - what you learn in one carries into the next.'
);
