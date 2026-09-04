<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 6;
race_handle_reset($L);

$s        = race_read($L, ['used' => false]);
$claimed  = race_ledger_count($L, 'claims');
$sessions = count(array_unique(race_ledger_rows($L, 'claims')));
$flag     = $claimed > 1 ? race_flag($L) : '';

race_render($L, [
    'form' => race_launcher('api.php?level=6', ['level' => 6, 'token' => 'sharedsession'], 6,
            'A - every request under ONE session id')
        . race_launcher('api.php?level=6', ['level' => 6, 'token' => ''], 6,
            'B - each request under its OWN session id')
        . '<p class="text-muted">Launcher B sends an empty token; the endpoint then gives each request a session of
           its own, which is what a second browser or a mobile app would produce. Run A first and read the
           interleaving log before running B.</p>',
    'result' => race_state_block($L, [
            'reward claimed flag' => $s['used'] ? 'true' : 'false',
            'times claimed'       => $claimed,
            'distinct sessions'   => $sessions,
        ], $claimed > 1
            ? 'Claimed ' . $claimed . ' times across ' . $sessions . ' sessions. The application code never changed - only whether your requests overlapped.'
            : 'Claimed ' . $claimed . ' time(s). If launcher A shows pids running one after another, that is the lock talking.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'The bug was there the whole time; the session lock was hiding it.',
]);
