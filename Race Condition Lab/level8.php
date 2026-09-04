<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 8;
race_handle_reset($L);

$arrivals = array_map('floatval', race_ledger_rows($L, 'arrivals'));
$best     = race_best_window(race_ledger_rows($L, 'arrivals'), 0.025);
$spread   = count($arrivals) > 1 ? (max($arrivals) - min($arrivals)) * 1000 : 0.0;
$flag     = $best >= 8 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=8', ['level' => 8], 12, 'Deliver requests inside one 25 ms window'),
    'result' => race_state_block($L, [
            'window'                   => '25 ms',
            'requests recorded'        => count($arrivals),
            'total spread'             => number_format($spread, 1) . ' ms',
            'best group inside window' => $best,
            'target'                   => 8,
        ], $best >= 8
            ? 'Eight or more requests landed together. Reset, turn warming off, and compare the spread.'
            : 'Turn connection warming on and raise the request count. Reset between attempts so old arrivals do not skew the spread.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => $best . ' requests arrived inside a 25 ms window.',
]);
