<?php
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/level_defs.php';

$L = 2;
race_handle_reset($L);

$s       = race_read($L, ['used' => false]);
$applied = race_ledger_count($L, 'applied');
$total   = 100.00 - 30.00 * $applied;
$flag    = $applied > 1 ? race_flag($L) : '';

race_render($L, [
    'form'   => race_launcher('api.php?level=2', ['level' => 2], 6, 'Apply coupon SAVE30, in parallel'),
    'result' => race_state_block($L, [
            'coupon marked used' => $s['used'] ? 'true' : 'false',
            'times applied'      => $applied,
            'order total'        => number_format($total, 2),
        ], $applied > 1
            ? 'The coupon is marked used once and the discount was applied ' . $applied . ' times.'
            : 'Applied ' . $applied . ' time(s). Send a burst while the validation call is still running.')
        . race_log_block($L),
    'flag'     => $flag,
    'flag_msg' => 'One coupon, ' . $applied . ' discounts.',
]);
