<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';
header('Content-Type: application/json');

$action = $_GET['action'] ?? '';
$body   = json_decode(file_get_contents('php://input'), true) ?? [];

if ($action === 'getUser') {
    $api_key      = $body['api_key'] ?? '';
    $requested_id = (int)($body['id'] ?? 0);

    // Validate API key exists (but NOT checking ownership!)
    $db   = get_db();
    $stmt = $db->prepare("SELECT id FROM users WHERE api_key = ?");
    $stmt->execute([$api_key]);
    $caller = $stmt->fetch();

    if (!$caller) {
        echo json_encode(['error' => 'Invalid API key']);
        exit;
    }

    // VULNERABLE: fetches ANY user's data without ownership check
    $stmt = $db->prepare("SELECT id, username, email, role, api_key FROM users WHERE id = ?");
    $stmt->execute([$requested_id]);
    $user = $stmt->fetch();

    $payload = $user ?: ['error' => 'User not found'];

    // Proof of the IDOR: a valid key retrieved a record that is not its own,
    // and that record is the admin's. Same gate as level7.php, so the direct
    // curl / fetch call the level documents earns the flag too.
    if ($user && $user['role'] === 'admin' && (int)$caller['id'] !== (int)$user['id']) {
        $payload['flag'] = get_flag_for_level(7);
    }

    echo json_encode($payload);
    exit;
}

echo json_encode(['error' => 'Unknown action']);
