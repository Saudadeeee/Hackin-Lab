<?php
/**
 * redirector.php — an OPEN REDIRECT hosted on the "trusted" feed host.
 *
 * It issues a 302 to whatever ?url= is supplied. In the redirect-based SSRF
 * level, an allowlist trusts the host of this redirector (feed.local) but the
 * fetcher follows the 302 onward to an internal address.
 */

$target = $_GET['url'] ?? '';

if ($target === '') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "redirector.php — supply ?url= to be redirected (302).\n";
    echo "Example: redirector.php?url=http://127.0.0.1/internal.php?level=5\n";
    exit;
}

// Open redirect: no validation of the destination whatsoever.
header('Location: ' . $target, true, 302);
echo "Redirecting to " . htmlspecialchars($target, ENT_QUOTES) . " ...\n";
