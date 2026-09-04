<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 4;
race_handle_reset($L);

$processed = race_ledger_count($L, 'hits');
$flag      = $processed > 3 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=4', ['level' => 4], 8, 'Call the limited endpoint, in parallel'),
    'result' => race_state_block($L, [
            'limit'              => 3,
            'limiter counter'    => $processed,
            'actually processed' => $processed,
        ], $processed > 3
            ? 'The counter now reports the overrun accurately, after the work was already done.'
            : 'Still within the limit. Send more requests than the limit, all at once.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => $processed . ' requests processed under a limit of 3.',
]);
