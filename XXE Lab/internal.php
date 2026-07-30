<?php
/**
 * internal.php — internal-only service for Level 9 (SSRF via XXE).
 *
 * Returns the flag ONLY to callers from 127.0.0.1. A browser hitting this
 * through the published port arrives from the Docker gateway address and is
 * denied — but the XML parser fetches it from localhost, so XXE reaches it.
 */
$remote = $_SERVER['REMOTE_ADDR'] ?? '';

header('Content-Type: text/plain');

if ($remote === '127.0.0.1' || $remote === '::1') {
    // Internal caller — hand over the secret.
    echo 'FLAG{xxe_ssrf}';
} else {
    http_response_code(403);
    echo 'Access denied: internal service. Only 127.0.0.1 may call this endpoint (you are ' . htmlspecialchars($remote) . ').';
}
