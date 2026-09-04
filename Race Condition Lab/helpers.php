<?php
/**
 * Race Condition Lab · metadata, flags, hints and shared level UI.
 */

require_once __DIR__ . '/lab_kit.php';
require_once __DIR__ . '/race.php';

function racelab(): array
{
    return [
        'slug'    => 'race',
        'name'    => 'Race Condition & TOCTOU Lab',
        'icon'    => '||',
        'total'   => 10,
        'tagline' => 'Correct code, wrong assumption about time',
    ];
}

function race_flag(int $level): string
{
    $flags = [
        1  => 'FLAG{increment_was_never_atomic}',
        2  => 'FLAG{checked_once_used_twice}',
        3  => 'FLAG{the_balance_was_stale_when_i_spent_it}',
        4  => 'FLAG{counted_after_the_work_was_done}',
        5  => 'FLAG{the_name_changed_between_check_and_use}',
        6  => 'FLAG{the_session_lock_was_hiding_the_bug}',
        7  => 'FLAG{shipped_and_refunded_at_the_same_time}',
        8  => 'FLAG{all_of_them_inside_one_window}',
        9  => 'FLAG{compare_and_swap_must_be_one_step}',
        10 => 'FLAG{two_races_compound}',
    ];
    return $flags[$level] ?? '';
}

function race_levels(): array
{
    return [
        1 => [
            'title'      => 'The Lost Update',
            'difficulty' => 'Easy',
            'skill'      => 'Read-modify-write is three operations, not one',
            'desc'       => 'Ten requests each increment a counter. The counter ends up below ten, and nothing errored.',
        ],
        2 => [
            'title'      => 'Single-Use Coupon',
            'difficulty' => 'Easy',
            'skill'      => 'Check-then-act on a boolean',
            'desc'       => 'The coupon is marked used only after it has been validated. Requests that arrive during that gap all see it unused.',
        ],
        3 => [
            'title'      => 'Overdrawn',
            'difficulty' => 'Easy',
            'skill'      => 'Check-then-act on a balance',
            'desc'       => 'The balance is checked, a payment call happens, then the debit is written. Concurrent withdrawals all pass the same check.',
        ],
        4 => [
            'title'      => 'Rate Limit Counted Too Late',
            'difficulty' => 'Medium',
            'skill'      => 'Ordering of the counter relative to the work',
            'desc'       => 'The limiter increments after the expensive operation completes, so a burst of requests all see a fresh quota.',
        ],
        5 => [
            'title'      => 'The Name Changed Underneath',
            'difficulty' => 'Medium',
            'skill'      => 'TOCTOU across two endpoints, validation on a value read twice',
            'desc'       => 'One endpoint validates the selected file, another changes it. The export re-reads the name after the check.',
        ],
        6 => [
            'title'      => 'Why Your Race Does Not Reproduce',
            'difficulty' => 'Hard',
            'skill'      => 'Recognising the thing that is serialising your requests',
            'desc'       => 'The same bug as level 2, but every request is serialised by a lock you did not know was there. Find it, then work around it.',
        ],
        7 => [
            'title'      => 'Shipped and Refunded',
            'difficulty' => 'Hard',
            'skill'      => 'Races between different endpoints over one state machine',
            'desc'       => 'Cancel and ship both require the order to be pending, and neither takes a lock. Run them together.',
        ],
        8 => [
            'title'      => 'Inside the Window',
            'difficulty' => 'Hard',
            'skill'      => 'Connection warming and synchronised delivery',
            'desc'       => 'This endpoint only counts requests that land within 25 ms of each other. Firing them at once is not enough.',
        ],
        9 => [
            'title'      => 'Optimistic Locking, Pessimistically Wrong',
            'difficulty' => 'Expert',
            'skill'      => 'Compare-and-swap must be a single atomic operation',
            'desc'       => 'A version column is read and compared, and then the write happens as a separate step. The check is real and useless.',
        ],
        10 => [
            'title'      => 'Compounding',
            'difficulty' => 'Expert',
            'skill'      => 'Chaining two independent windows',
            'desc'       => 'Buying and refunding each have their own window. Buying alone gains nothing; the refund window is where the money comes from.',
        ],
    ];
}

function race_hints(int $level): array
{
    $h = [
        1 => [
            '<code>$n = $n + 1</code> is three machine steps: load, add, store. Two processes can load the same value before either stores.',
            'The acknowledgement ledger is appended to, so it counts every request that completed. The counter is read-modify-written, so it does not.',
            'Fire ten requests in parallel and compare the two numbers. A gap between them is a lost update - data quietly destroyed with no error anywhere.',
            'Use the launcher with 10 requests and connection warming enabled, then reload the page.',
            'Any run where acknowledgements exceed the counter earns the flag. If they match, raise the request count.',
        ],
        2 => [
            'Read the endpoint in order: it checks <code>used</code>, then does work, then sets <code>used</code>. Everything that arrives during the work sees the old value.',
            'This is the check-then-act pattern. The bug is not the check and not the act - it is that they are separate, with the state readable in between.',
            'You do not need to be clever about timing here: the window is over a hundred milliseconds wide.',
            'Fire several requests in parallel with the same coupon code.',
            'Launcher, 5 requests. The flag appears once the coupon has been applied more than once.',
        ],
        3 => [
            'The same shape as the previous level with a number instead of a boolean: check <code>balance &gt;= 100</code>, do work, subtract.',
            'Each concurrent request reads a balance that has not been debited yet, so each one believes there is enough.',
            'The account holds 100. Withdrawing 200 in total is proof the check was decided on stale data.',
            'Fire parallel withdrawals and watch the balance go negative in the state table.',
            'Launcher, 4 requests. The flag appears once withdrawn is at least 200.',
        ],
        4 => [
            'Find the increment. It is after the work, not before, so the quota is only spent once the request has already had its effect.',
            'A limiter has to reserve capacity before doing the work, and release it afterwards if the work fails. This one does the opposite.',
            'The limit is 3 per window. Requests that all arrive before any of them finishes will all see a count below the limit.',
            'Send more requests in parallel than the limit allows.',
            'Launcher, 8 requests. The flag appears once processed exceeds the limit of 3.',
        ],
        5 => [
            'Two endpoints share one piece of state: the selected filename. One validates it, the other changes it.',
            'The export endpoint reads the name, checks the extension, does work, and then <strong>reads the name again</strong>. Those two reads can disagree.',
            'So the plan is: start an export while <code>notes.txt</code> is selected, and switch the selection to <code>vault.key</code> during the work window.',
            'Fire the export and the selection change together. The export\'s window is about 160 ms, so the switch has plenty of room.',
            'Use the two launchers side by side: send the export first, then immediately send the select. Repeat if the timing misses; then submit the exported value.',
        ],
        6 => [
            'The logic is identical to level 2, so if parallel requests are not reproducing it, something is stopping them from running in parallel.',
            'Look at the endpoint source: it calls <code>session_start()</code>. PHP takes an exclusive lock on the session file and holds it for the whole request.',
            'Requests sharing a session id therefore queue up one behind another. Your race is being serialised by the platform, not fixed by the application.',
            'The account can hold several sessions at once. Requests under <em>different</em> session ids are not serialised against each other.',
            'Use the token field to send each parallel request with a different session id. The state they race over is per-account, so the bug is still there.',
        ],
        7 => [
            'Two endpoints, one precondition: <code>status === "pending"</code>. Neither locks the order while it works.',
            'Both read pending, both do their work, both write their own terminal status. The second write wins the status field, but the side effects of the first already happened.',
            'The goal is an order that has both <code>refunded</code> and <code>shipped</code> set - a state the state machine cannot legally reach.',
            'Fire cancel and ship at the same moment rather than firing many copies of one of them.',
            'Use the two launchers together, one request each. Repeat until both flags are set on the order.',
        ],
        8 => [
            'This endpoint records arrival times. Requests that arrive more than 25 ms after the first do not count.',
            'The first request on a fresh connection pays for a TCP handshake and for PHP starting up. That easily costs more than the window.',
            'So warm the connections first: send a throwaway request on each one, then send the real batch over connections that are already open.',
            'Enable warming in the launcher and raise the request count. Watch the reported spread come down.',
            'This is the browser version of the single-packet attack: minimise per-connection setup so the requests arrive together rather than in a queue.',
        ],
        9 => [
            'The version check is genuine: it re-reads the row and compares. It is still useless, and the reason is in the ordering.',
            'Between the comparison and the write there is another gap. Two requests can both pass the comparison before either writes.',
            'A correct compare-and-swap is one operation the storage layer performs atomically - <code>UPDATE ... WHERE id = ? AND version = ?</code>, then check the affected row count.',
            'Each purchase writes <code>balance = read_balance - 50</code> using the value read <em>before</em> the work, so a lost update also loses the other purchase\'s debit.',
            'Fire parallel purchases; the flag appears when spent exceeds the balance that was actually available.',
        ],
        10 => [
            'Two windows exist here: the buy path checks the balance before debiting, and the refund path checks that you hold a credit before paying out.',
            'A credit bought and refunded once returns exactly what it cost, so the gain has to come from the refund window rather than from the trade itself.',
            'The refund checks that you hold a credit and only consumes it afterwards, so concurrent refunds all read the same credit.',
            'Order matters: a credit has to exist before any refund will do anything. Buy one first, then send the refunds together.',
            'Buy a single credit, reload, then fire a parallel burst of refunds. Repeat the cycle until the balance passes 200.',
        ],
    ];
    return $h[$level] ?? [];
}

/** State table plus a reset control. Every level shows the same furniture. */
function race_state_block(int $level, array $rows, string $note = ''): string
{
    $tr = '';
    foreach ($rows as $k => $v) {
        $tr .= '<tr><td>' . lk_esc((string)$k) . '</td><td>' . lk_esc((string)$v) . '</td></tr>';
    }
    return '<div class="lk-box"><h4><span class="lk-tag">STATE</span>Current server state</h4><div class="lk-body">'
        . '<table class="lk-kv">' . $tr . '</table>'
        . ($note !== '' ? '<p class="text-muted" style="margin-top:0.5rem">' . $note . '</p>' : '')
        . '<form method="post" style="margin-top:0.7rem"><input type="hidden" name="_reset" value="1">'
        . '<button class="btn btn-outline" type="submit">Reset this level</button></form>'
        . '</div></div>';
}

/** Handle the reset button. Call before reading state. */
function race_handle_reset(int $level): void
{
    if (!empty($_POST['_reset'])) {
        race_reset($level);
        race_log_clear($level);
        race_ledger_clear_all($level);
        @unlink(race_state_dir() . '/' . race_sid() . '-l' . $level . '.acks');
        header('Location: level' . $level . '.php');
        exit;
    }
}

function race_extra_head(): string
{
    return '<style>.rl .form-control{display:inline-block;width:auto}</style>';
}

/**
 * Render a level page by merging its prose definition with the runtime pieces
 * the level page computed (state block, launchers, flag).
 */
function race_render(int $L, array $over): void
{
    $def  = race_def($L);
    $meta = race_levels()[$L];

    lk_page(array_merge([
        'lab'        => racelab(),
        'level'      => $L,
        'title'      => $meta['title'],
        'difficulty' => $meta['difficulty'],
        'extra_head' => race_extra_head(),
        'hints'      => race_hints($L),
        'flag'       => '',
    ], $def, $over));
}
