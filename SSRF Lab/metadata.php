<?php
/**
 * metadata.php — MOCK cloud instance-metadata service.
 *
 * Served internally at http://169.254.169.254/ (that link-local address is
 * added to the container's loopback at startup, so only the server itself can
 * reach it). Apache rewrites /latest/meta-data/* to this file via .htaccess.
 *
 * Mirrors the AWS IMDSv1 layout closely enough to teach credential theft.
 */
require_once __DIR__ . '/helpers.php';

header('Content-Type: text/plain; charset=utf-8');

// Only the server (loopback or the 169.254.x link-local metadata IP) may read this.
$remote = $_SERVER['REMOTE_ADDR'] ?? '';
$isInternal = in_array($remote, ['127.0.0.1', '::1'], true)
    || strncmp($remote, '127.', 4) === 0
    || strncmp($remote, '169.254.', 8) === 0;

if (!$isInternal) {
    http_response_code(403);
    echo "403 Forbidden — instance metadata is only reachable from the instance itself.\n";
    echo "Your request originated from: {$remote}\n";
    exit;
}

$path = trim($_GET['path'] ?? '', '/');
$role = 'ssrf-lab-role';

switch (true) {
    case $path === '' || $path === 'latest' || $path === 'latest/meta-data':
        echo "ami-id\n";
        echo "hostname\n";
        echo "instance-id\n";
        echo "iam/\n";
        break;

    case $path === 'iam/security-credentials'
      || $path === 'iam/security-credentials/':
        // The role name — the next hop an attacker enumerates.
        echo $role . "\n";
        break;

    case $path === 'iam/security-credentials/' . $role:
        // The prize: temporary credentials. The leaked token carries the flag.
        $creds = [
            'Code'            => 'Success',
            'LastUpdated'     => date('c'),
            'Type'            => 'AWS-HMAC',
            'AccessKeyId'     => 'ASIASSRFLABEXAMPLE',
            'SecretAccessKey' => get_flag_for_level(8),
            'Token'           => 'IQoJb3JpZ2luX2VjE' . base64_encode(get_flag_for_level(8)),
            'Expiration'      => date('c', time() + 3600),
        ];
        echo json_encode($creds, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        break;

    case $path === 'instance-id':
        echo "i-0ssrf1ab00000000\n";
        break;

    case $path === 'hostname':
        echo "ssrf-lab.internal\n";
        break;

    default:
        http_response_code(404);
        echo "404 - Not Found: /{$path}\n";
        break;
}
