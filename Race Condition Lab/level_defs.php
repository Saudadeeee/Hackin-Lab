<?php
/**
 * Per-level teaching content. Kept out of the level pages so each of those
 * stays short enough to read as "the challenge logic" rather than as prose.
 */

function race_def(int $level): array
{
    $defs = [];

/* ------------------------------------------------------------------ 1 */
$defs[1] = [
    'code' => <<<'PHP'
// POST /api/counter
$s    = read_state();          // 1. LOAD
$seen = $s['counter'];

do_some_work();                // render, log, call another service

$s['counter'] = $seen + 1;     // 2. ADD  (to the value loaded earlier)
write_state($s);               // 3. STORE

append_ack();                  // append-only ledger: counts every request
PHP,
    'vuln_lines' => [2, 3, 7, 8],
    'annotation' => 'Incrementing a shared value is a load, an add and a store. Between the load and the store the
        value is visible to everyone else, and any other request that loads it in that interval will compute its
        result from the same starting point. Both then store, and one of the two increments disappears.',
    'theory' => '<p>Nothing here throws an exception, logs a warning, or returns an error. Two requests both
        succeed, both report success to the user, and one of the two effects is silently gone. That is what makes
        lost updates hard to find in production: the failure mode is quiet.</p>
        <p>The width of the window is whatever sits between the load and the store - a template render, a log write,
        an HTTP call to another service. In a busy application it is routinely tens of milliseconds, which is
        enormous compared to how quickly an attacker can deliver a second request.</p>
        <p>The fix is never "read more carefully". It is to stop reading and writing as separate operations:
        <code>UPDATE t SET n = n + 1</code> pushes the arithmetic into the database, where it happens under a row
        lock you did not have to write.</p>',
    'fix' => [
        'bad' => <<<'PHP'
$n = (int) $db->query('SELECT n FROM counters WHERE id = 1')->fetchColumn();
$db->exec('UPDATE counters SET n = ' . ($n + 1) . ' WHERE id = 1');
PHP,
        'good' => <<<'PHP'
// Let the storage layer do the arithmetic, atomically, under its own lock.
$db->prepare('UPDATE counters SET n = n + 1 WHERE id = ?')->execute([1]);

// Redis:      INCR key
// Postgres:   UPDATE ... SET n = n + 1 RETURNING n
// In-process: an atomic integer, or a mutex around the whole sequence
PHP,
        'note' => 'If the new value is needed, use <code>RETURNING</code> or <code>INCR</code>\'s return value.
            Re-reading after the update reintroduces the same gap in a different place.',
    ],
    'scenario' => '<strong>Scenario:</strong> a counter incremented by an endpoint that does a little work between
        reading and writing.
        <br><strong>Goal:</strong> make the acknowledgement ledger and the counter disagree.',
    'model' => [
        'title' => 'Two requests, drawn out',
        'html'  => '<pre class="lk-sinkline">A: load n=0 ........ add ........ store n=1
B:       load n=0 ........ add ........ store n=1
                                        ^ one increment lost</pre>
        <p>Both requests are correct in isolation. The defect only exists in the relationship between them, which
        is why unit tests never catch it and why the code reads perfectly well.</p>',
    ],
    'why' => '<p>The interleaving log shows two pids reading the same value before either wrote. The ledger counted
        every request that ran; the counter counted only the last writer in each overlapping group. The difference
        is the number of updates that were destroyed.</p>
        <p>Note that no request failed. Had this been a stock level, an audit balance or a message sequence number,
        the application would now be quietly inconsistent with no error to trace back to.</p>',
];

/* ------------------------------------------------------------------ 2 */
$defs[2] = [
    'code' => <<<'PHP'
// POST /api/coupon
$s = read_state();
if ($s['used']) {                    // TIME OF CHECK
    return 'rejected: coupon already used';
}

validate_with_promo_service();       // ~140 ms

$s = read_state();                   // TIME OF USE
$s['used']    = true;
$s['applied'] = $s['applied'] + 1;
$s['total']   = $s['total'] - 30.00;
write_state($s);
PHP,
    'vuln_lines' => [3, 4, 7, 9],
    'annotation' => 'The coupon is only marked as used after the validation call returns. Every request that
        arrives during that call reads <code>used = false</code> and is therefore allowed through.',
    'theory' => '<p>Check-then-act is the most common shape of race condition in web applications, and it is easy
        to miss during review because both halves are obviously correct. The check really does check. The action
        really does mark the coupon used. What is missing is any guarantee that no one else ran between them.</p>
        <p>The tell is a state variable that is <em>read</em> to make a decision and <em>written</em> later in the
        same request. If nothing holds a lock across those two points, the decision was made against a value that
        could already be out of date.</p>
        <p>Look for this wherever a business rule says "only once": a coupon, an invite code, a signup bonus, a
        free trial, a one-time password, a withdrawal from a gift card balance.</p>',
    'fix' => [
        'bad' => <<<'PHP'
if ($coupon['used']) { return deny(); }
// ... work ...
$db->exec("UPDATE coupons SET used = 1 WHERE code = '$code'");
PHP,
        'good' => <<<'PHP'
// Make the claim itself the check. One statement, decided by the database.
$st = $db->prepare('UPDATE coupons SET used = 1, used_by = ?
                    WHERE code = ? AND used = 0');
$st->execute([$userId, $code]);

if ($st->rowCount() === 0) {
    return deny('coupon already used');   // someone else claimed it first
}
// Only now do the work. If the work fails, roll the claim back explicitly.
PHP,
        'note' => 'The pattern is "claim, then act", not "check, then act". A unique constraint on
            <code>(coupon_code, order_id)</code> gives you the same guarantee from a different direction: the second
            insert fails instead of succeeding.',
    ],
    'scenario' => '<strong>Scenario:</strong> a checkout that accepts one promotional code per order.
        <br><strong>Goal:</strong> apply the same code more than once.',
    'model' => [
        'title' => 'Where the window is',
        'html'  => '<pre class="lk-sinkline">read used=false ─┐
                 │  <-- every request arriving here passes the check
   ~140 ms work  │
                 │
write used=true ─┘</pre>
        <p>The window is as wide as the work. You do not need precise timing; you need to arrive at any point inside
        it. That is why a plain parallel burst is enough here and why level 8 exists to show what it looks like when
        the window is genuinely narrow.</p>',
    ],
    'why' => '<p>Each request in your burst read <code>used = false</code>, because none of the writes had happened
        yet. All of them passed the check honestly, and all of them then applied the discount.</p>
        <p>The final state shows the coupon marked used - exactly once. The flag is that the discount was applied
        more times than that.</p>',
];

/* ------------------------------------------------------------------ 3 */
$defs[3] = [
    'code' => <<<'PHP'
// POST /api/withdraw
$s = read_state();
if ($s['balance'] < 100) {           // TIME OF CHECK
    return 'rejected: insufficient funds';
}

call_payment_rail();                 // ~150 ms

$s = read_state();                   // TIME OF USE
$s['balance']   = $s['balance']   - 100;
$s['withdrawn'] = $s['withdrawn'] + 100;
write_state($s);
PHP,
    'vuln_lines' => [3, 4, 7, 9, 10],
    'annotation' => 'The balance is checked before an external call and debited after it. Concurrent withdrawals
        all read the pre-debit balance, all pass, and all debit - taking the account below zero.',
    'theory' => '<p>This is check-then-act again, with a number instead of a boolean, and it is worth doing
        separately because the mitigation people reach for first does not work. Adding a constraint like
        <code>CHECK (balance &gt;= 0)</code> helps, but only converts the race into a failed transaction at a random
        point, often after the external payment call has already been made.</p>
        <p>The durable fix is to make the debit conditional and atomic:
        <code>UPDATE accounts SET balance = balance - 100 WHERE id = ? AND balance &gt;= 100</code>, then act on
        the affected row count. That way the decision and the effect are the same operation.</p>
        <p>Where an external side effect is involved, add a second layer: reserve the funds first, call the
        provider, then settle or release. A reservation is a row that exists, so it cannot be lost the way an
        in-memory decision can.</p>',
    'fix' => [
        'bad' => <<<'PHP'
if ($balance < $amount) { return deny(); }
charge_card();
$db->exec("UPDATE accounts SET balance = balance - $amount WHERE id = $id");
PHP,
        'good' => <<<'PHP'
// Reserve atomically. The WHERE clause is the check.
$st = $db->prepare('UPDATE accounts SET balance = balance - :amt
                    WHERE id = :id AND balance >= :amt');
$st->execute(['amt' => $amount, 'id' => $id]);

if ($st->rowCount() === 0) {
    return deny('insufficient funds');
}
try {
    charge_card();                       // side effect AFTER the funds are held
} catch (Throwable $e) {
    $db->prepare('UPDATE accounts SET balance = balance + :amt WHERE id = :id')
       ->execute(['amt' => $amount, 'id' => $id]);
    throw $e;
}
PHP,
        'note' => 'Alternatively hold the row for the duration with <code>SELECT ... FOR UPDATE</code> inside a
            transaction. That serialises concurrent withdrawals at the cost of holding a lock across the external
            call, which is usually the wrong trade.',
    ],
    'scenario' => '<strong>Scenario:</strong> an account holding 100, and a withdrawal endpoint that talks to a
        payment rail between the check and the debit.
        <br><strong>Goal:</strong> withdraw more than the account contains.',
    'model' => [
        'title' => 'What "insufficient funds" actually checked',
        'html'  => '<p>The check answered: <em>was there enough money when I looked?</em> The question that
        mattered was: <em>is there enough money at the moment I take it?</em></p>
        <p>Those coincide only when nothing else can act in between. Concurrency removes that guarantee, and no
        amount of care inside a single request restores it.</p>',
    ],
    'why' => '<p>Each request read a balance of 100 before any debit had been written, so each passed the check.
        The debits then applied one after another, and the account went negative.</p>
        <p>Look at the interleaving log: the reads cluster at the start, the writes cluster at the end. Everything
        between them was decided on the same stale number.</p>',
];

/* ------------------------------------------------------------------ 4 */
$defs[4] = [
    'code' => <<<'PHP'
// POST /api/expensive  - limit: 3 per window
$s = read_state();
if ($s['hits'] >= 3) {
    return 'rejected: rate limit';
}

do_expensive_thing();                // ~130 ms  <- the thing being limited

$s = read_state();
$s['hits']      = $s['hits'] + 1;    // quota spent only now
$s['processed'] = $s['processed'] + 1;
write_state($s);
PHP,
    'vuln_lines' => [3, 4, 6, 9],
    'annotation' => 'The quota is consumed after the protected operation rather than before it. A burst that
        arrives while the first requests are still working sees a counter that has not moved.',
    'theory' => '<p>A rate limiter is a reservation system. Reserving after the fact is like taking payment after
        the meal and hoping nobody leaves. The correct ordering is: increment first, and if the increment pushes
        you past the limit, reject and (optionally) decrement again.</p>
        <p>The second requirement is that the increment itself be atomic - which is a level 1 problem wearing a
        different hat. <code>INCR</code> in Redis returns the new value in one operation, which is why almost every
        production limiter is built on it.</p>
        <p>This matters beyond throughput. Limiters guard OTP attempts, password guesses, coupon redemptions and
        expensive report generation. A limiter that can be overrun by a factor of ten is not a limiter; it is a
        speed bump that also gives you a false sense of coverage.</p>',
    'fix' => [
        'bad' => <<<'PHP'
if ($hits >= LIMIT) { return deny(); }
do_expensive_thing();
$redis->incr($key);
PHP,
        'good' => <<<'PHP'
// Reserve first, atomically, and decide from the value the store returns.
$n = $redis->incr($key);
if ($n === 1) { $redis->expire($key, WINDOW_SECONDS); }

if ($n > LIMIT) {
    return deny('rate limit');       // no work performed
}
do_expensive_thing();

// For anything security-relevant (OTP, login), also lock the account after
// N failures. A limiter alone gives an attacker unlimited attempts spread
// over unlimited windows.
PHP,
        'note' => 'A sliding-window or token-bucket limiter changes the accounting, not the ordering. Increment
            before the work regardless of which algorithm you pick.',
    ],
    'scenario' => '<strong>Scenario:</strong> an endpoint limited to three calls per window, where the counter is
        updated once the work finishes.
        <br><strong>Goal:</strong> get more than three requests processed.',
    'model' => [
        'title' => 'Reserve, then act',
        'html'  => '<table class="lk-kv">
            <tr><td>wrong</td><td>check &rarr; work &rarr; increment</td></tr>
            <tr><td>right</td><td>increment &rarr; check the returned value &rarr; work</td></tr>
        </table>
        <p>The overrun factor is roughly "how many requests fit inside the work duration". With a 130 ms operation
        and a burst of eight, all eight see a count of zero.</p>',
    ],
    'why' => '<p>Every request in the burst read the counter before any of them had finished working, so every one
        of them saw a count below the limit. The increments then all applied, leaving a counter that correctly
        reports the overrun - after the fact.</p>',
];

/* ------------------------------------------------------------------ 5 */
$defs[5] = [
    'code' => <<<'PHP'
// POST /api/export
$name = read_state()['file'];        // TIME OF CHECK
if (!str_ends_with($name, '.txt')) {
    return 'rejected: only .txt may be exported';
}

render_export_and_write_audit_row(); // ~160 ms

$name = read_state()['file'];        // TIME OF USE - read AGAIN
return read_file($name);

// POST /api/select?to=...  - a different endpoint, no coordination
write_state(['file' => $_GET['to']]);
PHP,
    'vuln_lines' => [2, 3, 4, 8, 9],
    'annotation' => 'The filename is read twice: once to validate it and once to use it. Nothing prevents another
        request from changing it in between, so the validated value and the used value can differ.',
    'theory' => '<p>Time-of-check to time-of-use is the general form of every level in this lab, but it is
        clearest here because the two reads are literally visible in the source. The rule is: <strong>validate the
        value you are going to use, not a value you will re-fetch later.</strong></p>
        <p>In filesystem code this appears as <code>is_writable()</code> then <code>fopen()</code>,
        <code>file_exists()</code> then <code>unlink()</code>, or a stat-then-open pair that a symlink swap can
        redirect. The kernel-level answer is to operate on a handle you already hold rather than on a path you
        re-resolve.</p>
        <p>In application code the equivalent is to validate the value and then pass <em>that value</em> forward,
        rather than re-reading it from shared state. If it has to come from storage, read it once inside the same
        transaction that uses it.</p>',
    'fix' => [
        'bad' => <<<'PHP'
$name = read_state()['file'];
if (!allowed($name)) { return deny(); }
do_work();
return read_file(read_state()['file']);      // re-read
PHP,
        'good' => <<<'PHP'
// Read once, validate that value, use that value.
$name = read_state()['file'];
if (!allowed($name)) {
    return deny();
}
do_work();
return read_file($name);                     // the value that was validated

// For real filesystem work, hold the handle across the check:
$fh = fopen($path, 'r');                     // resolve the path ONCE
if (!allowed(fstat($fh))) { fclose($fh); return deny(); }
return stream_get_contents($fh);             // same inode, guaranteed
PHP,
        'note' => 'The one-line version: pass the validated value, never the pointer to it.',
    ],
    'scenario' => '<strong>Scenario:</strong> an export feature that only allows <code>.txt</code> files, and a
        separate endpoint that changes which file is selected.
        <br><strong>Goal:</strong> export <code>vault.key</code> and submit its contents.',
    'model' => [
        'title' => 'Two requests, two endpoints',
        'html'  => '<pre class="lk-sinkline">export:  read "notes.txt" ── check ok ── work ────────── read again ── send
select:                            write "vault.key"</pre>
        <p>The select only has to land somewhere inside the export\'s 160 ms of work. Send the export first, then
        the select immediately afterwards; if you miss, reset and try again - the window is wide enough that a
        couple of attempts will do it.</p>',
    ],
    'why' => '<p>The check ran against <code>notes.txt</code> and passed. During the work, the other endpoint
        replaced the selection, and the second read returned <code>vault.key</code>. The validation was correct and
        applied to a value that no longer mattered.</p>
        <p>The interleaving log makes this concrete: the check line and the export line name different files.</p>',
];

/* ------------------------------------------------------------------ 6 */
$defs[6] = [
    'code' => <<<'PHP'
// POST /api/claim-reward
session_id($_POST['token']);
session_start();                     // <- exclusive lock on the session file,
                                     //    held for the whole request

$s = read_reward_state();            // per-ACCOUNT state, not per-session
if ($s['used']) {
    return 'rejected: reward already claimed';
}
process_reward();                    // ~150 ms
$s['used']    = true;
$s['claimed'] = $s['claimed'] + 1;
write_reward_state($s);
PHP,
    'vuln_lines' => [2, 3, 6, 7],
    'annotation' => 'The application bug is the same check-then-act as level 2. What is different is that
        <code>session_start()</code> serialises every request carrying the same session id, so a naive parallel
        burst runs one at a time and the bug appears to be absent.',
    'theory' => '<p>This level is about a failure of <em>testing</em>, not of the application. PHP\'s default
        session handler opens the session file with an exclusive lock and holds it until the script ends or calls
        <code>session_write_close()</code>. Requests sharing a session id therefore queue.</p>
        <p>The practical consequence is that a great many real race conditions are missed, because the tester fires
        twenty requests from one browser, sees them execute sequentially, and concludes the code is safe. The
        serialisation is incidental - it comes from the session layer, not from any deliberate concurrency control -
        and it disappears the moment requests arrive under different session ids, which is exactly what happens
        when an account is logged in from two devices.</p>
        <p>Equivalent things to look for elsewhere: a single-threaded dev server, a connection pool of size one,
        an in-process mutex that does not exist across workers, a queue consumer running with concurrency 1 in
        staging and 8 in production.</p>',
    'fix' => [
        'bad' => <<<'PHP'
session_start();                 // accidental serialisation, per session only
if ($s['used']) { return deny(); }
// ... work ...
$s['used'] = true;
PHP,
        'good' => <<<'PHP'
// Do not rely on the session lock for correctness - it only covers requests
// that share a session, and holding it across slow work destroys throughput.
session_start();
$user = $_SESSION['user'];
session_write_close();           // release early, deliberately

// Then protect the shared resource properly, at the account level:
$st = $db->prepare('UPDATE rewards SET claimed = 1
                    WHERE user_id = ? AND claimed = 0');
$st->execute([$user]);
if ($st->rowCount() === 0) {
    return deny('already claimed');
}
process_reward();
PHP,
        'note' => 'When a race will not reproduce, first prove your requests actually overlap. The interleaving log
            on this page is the cheap way to do that: sequential pids mean sequential execution.',
    ],
    'scenario' => '<strong>Scenario:</strong> a one-per-account reward claim. Parallel requests from one session
        do not reproduce the bug. The account can hold several concurrent sessions.
        <br><strong>Goal:</strong> claim the reward more than once.',
    'model' => [
        'title' => 'Diagnose before you conclude',
        'html'  => '<ol>
            <li>Fire the burst with a single token and read the interleaving log. If the pids run one after another,
                your requests never overlapped.</li>
            <li>Ask what is serialising them. Session locks, single-worker servers and per-connection database
                transactions are the usual candidates.</li>
            <li>Remove the serialisation - here, by giving each request a different session id - and re-run.</li>
        </ol>
        <p>The launcher on this page sends a distinct token per request when the option is enabled, so you can
        compare the two logs directly.</p>',
    ],
    'why' => '<p>With distinct session ids nothing held a shared lock, so the requests overlapped and the
        check-then-act window opened. The application code did not change between the failing and the succeeding
        attempt; only the conditions under which you tested it did.</p>
        <p>Keep the diagnostic habit: "it did not reproduce" is a statement about your test, not about the code,
        until you have evidence that the requests were genuinely concurrent.</p>',
];

/* ------------------------------------------------------------------ 7 */
$defs[7] = [
    'code' => <<<'PHP'
// POST /api/order?op=ship
if ($order['status'] !== 'pending') { return deny(); }
reserve_stock_and_print_label();     // ~150 ms
$order['status']  = 'shipped';
$order['shipped'] = true;
save($order);

// POST /api/order?op=cancel        - separate handler, no shared lock
if ($order['status'] !== 'pending') { return deny(); }
refund_via_payment_provider();       // ~150 ms
$order['status']   = 'cancelled';
$order['refunded'] = true;
save($order);
PHP,
    'vuln_lines' => [2, 3, 8, 9],
    'annotation' => 'Two handlers guard the same transition with the same precondition and neither holds the order
        while it works. Run together, both observe <code>pending</code>, both perform their side effect, and the
        order ends up in a state the state machine does not have.',
    'theory' => '<p>Most race-condition testing fires many copies of one request. This class needs a different
        instinct: find two <em>different</em> operations that share a precondition, and run those together.</p>
        <p>The damage is not the inconsistent status field - it is the side effects. A refund was issued and a
        shipment was created. Reconciling that afterwards is a manual, financial problem, and the application will
        happily report the order as simply "shipped".</p>
        <p>Where to look: cancel versus fulfil, approve versus reject, close versus reopen, delete versus share,
        unsubscribe versus renew. Anywhere a workflow has two exits from one state.</p>',
    'fix' => [
        'bad' => <<<'PHP'
if ($order['status'] !== 'pending') { return deny(); }
do_side_effect();
$order['status'] = $newStatus;
save($order);
PHP,
        'good' => <<<'PHP'
// Make the transition itself the guard, and do it before the side effect.
$st = $db->prepare('UPDATE orders SET status = :to
                    WHERE id = :id AND status = :from');
$st->execute(['to' => $newStatus, 'id' => $id, 'from' => 'pending']);

if ($st->rowCount() === 0) {
    return deny('order is no longer pending');
}
do_side_effect();                    // only the winner gets here

// Side effects that cannot be rolled back (a refund, an email) belong behind
// an outbox row written in the same transaction as the status change.
PHP,
        'note' => 'One atomic transition per state change, and every side effect downstream of it. If two handlers
            can win the same transition, the state machine is not being enforced anywhere.',
    ],
    'scenario' => '<strong>Scenario:</strong> an order that is currently <code>pending</code>, with a ship
        endpoint and a cancel endpoint.
        <br><strong>Goal:</strong> reach an order that is both refunded and shipped.',
    'model' => [
        'title' => 'Race two different things',
        'html'  => '<pre class="lk-sinkline">ship:   read pending ── label printed ── status=shipped
cancel: read pending ── refund sent ──── status=cancelled</pre>
        <p>Whichever writes last owns the status field. Both side effects already happened, so the flag condition
        is <code>refunded &amp;&amp; shipped</code>, not any particular final status.</p>
        <p>Send one of each, at the same time. More copies of either one will not help.</p>',
    ],
    'why' => '<p>Both handlers evaluated <code>status === "pending"</code> against the same stored value, because
        neither had written yet. Each then completed its own side effect and wrote its own terminal status.</p>
        <p>The order now records a state that no legal sequence of transitions can produce - which is exactly the
        sort of inconsistency that reconciliation jobs and support teams end up absorbing.</p>',
];

/* ------------------------------------------------------------------ 8 */
$defs[8] = [
    'code' => <<<'PHP'
// POST /api/window
$now = microtime(true);
$s   = read_state();

if ($s['first'] <= 0 || $now - $s['first'] > 0.400) {
    $s['first'] = $now; $s['inWindow'] = 1;      // new group
} else {
    $s['inWindow']++;
}
if (($now - $s['first']) * 1000 <= 25.0) {      // 25 ms window
    $s['best'] = max($s['best'], $s['inWindow']);
}
write_state($s);
PHP,
    'vuln_lines' => [8, 9],
    'annotation' => 'This level is not about a flaw in the code. It is about delivery: the window is 25 ms wide,
        and the per-connection setup cost of a cold request is larger than that. Requests have to be made to arrive
        together, not merely sent together.',
    'theory' => '<p>Real race windows are often microseconds. Reaching them needs the requests to arrive
        simultaneously, and several things get in the way: the TCP handshake, TLS negotiation, DNS, PHP-FPM or
        Apache spawning a worker, and the first query warming a connection pool.</p>
        <p>The standard countermeasures are the ones this launcher exposes. <strong>Warm the connections</strong> by
        sending a throwaway request on each one first, so the handshake is already paid for. <strong>Pre-build the
        request bodies</strong> so no work happens between the sends. Over HTTP/1.1 that is roughly as far as a
        browser can go.</p>
        <p>Outside the browser, the technique goes further: with HTTP/2 you can put many requests in a
        <em>single packet</em> so the server receives them in one read, which removes network jitter from the
        equation entirely. That is what Burp\'s single-packet attack does, and it is why it reaches windows that
        parallel connections cannot.</p>',
    'fix' => [
        'bad' => <<<'PHP'
// Nothing to fix here - this level is the attacker's problem, not the app's.
// The defensive lesson is the mirror image:
if ($requestsWithin25ms > 1) { /* we assumed this could not happen */ }
PHP,
        'good' => <<<'PHP'
// Do not reason about how narrow a window is. Assume it will be hit.
//
// A window you have measured at 200 microseconds is still reachable by an
// attacker who can align requests to arrive in one TCP segment. Timing is
// not a security control; atomicity is.
$db->beginTransaction();
$row = $db->query('SELECT ... FOR UPDATE')->fetch();
// ...
$db->commit();
PHP,
        'note' => 'When a report says "theoretically possible but the window is only a few milliseconds", treat it
            as reachable. Modern tooling closed that gap years ago.',
    ],
    'scenario' => '<strong>Scenario:</strong> an endpoint that records arrival times and only counts requests
        landing within 25 ms of the first.
        <br><strong>Goal:</strong> get 8 or more requests inside one window.',
    'model' => [
        'title' => 'What you are fighting',
        'html'  => '<table class="lk-kv">
            <tr><td>TCP handshake</td><td>one round trip, per connection, paid once</td></tr>
            <tr><td>worker startup</td><td>the first request on a fresh Apache child is slower</td></tr>
            <tr><td>browser scheduling</td><td>connections open at slightly different moments</td></tr>
        </table>
        <p>Warming removes the first two. Watch the reported spread with warming off and on - the difference is the
        whole lesson, and it is the same reason attackers warm connections before a real race.</p>',
    ],
    'why' => '<p>With connections already open, the only remaining cost was writing the request bytes, so the
        requests arrived within a few milliseconds of each other rather than being spread across handshakes.</p>
        <p>Carry the general point forward: the width of a window tells you how much effort an attack needs, not
        whether it is possible.</p>',
];

/* ------------------------------------------------------------------ 9 */
$defs[9] = [
    'code' => <<<'PHP'
// POST /api/purchase  - "we use optimistic locking"
$row     = read_state();
$balance = $row['balance'];
$version = $row['version'];

build_order_and_call_gateway();      // ~140 ms

$cur = read_state();
if ($cur['version'] !== $version) {  // the CHECK
    return 'rejected: someone else modified the row';
}
                                     // <- gap
write_state([                        // the WRITE
    'balance' => $balance - 50,      // computed from the STALE read
    'version' => $version + 1,
]);
PHP,
    'vuln_lines' => [9, 10, 12, 13, 14],
    'annotation' => 'The version comparison is real, and it is still a check-then-act: two requests can both pass
        the comparison before either writes. The write then uses a balance read before the work, so it also
        overwrites the other request\'s debit.',
    'theory' => '<p>Optimistic concurrency control works only when the comparison and the write are one operation
        that the storage engine performs atomically. Splitting them - read the version, compare it in application
        code, then write - reintroduces exactly the window the technique exists to close.</p>
        <p>The correct form puts the comparison in the <code>WHERE</code> clause and uses the affected row count as
        the answer:</p>
        <pre class="lk-sinkline">UPDATE t SET v = :old + 1, ... WHERE id = :id AND v = :old</pre>
        <p>Then exactly one concurrent writer sees <code>rowCount() === 1</code> and the rest see zero and retry.
        This level also stacks a lost update on top: the new balance is computed from a value read before the work,
        so a stale write discards whatever happened in between. Both defects come from the same habit of treating
        "read" and "write" as independent steps.</p>',
    'fix' => [
        'bad' => <<<'PHP'
$row = select();
// ... work ...
if (select()['version'] !== $row['version']) { return deny(); }
update(['balance' => $row['balance'] - 50, 'version' => $row['version'] + 1]);
PHP,
        'good' => <<<'PHP'
// One statement. The comparison is part of the write.
$st = $db->prepare(
    'UPDATE accounts
        SET balance = balance - :amt, version = version + 1
      WHERE id = :id AND version = :v AND balance >= :amt'
);
$st->execute(['amt' => 50, 'id' => $id, 'v' => $version]);

if ($st->rowCount() === 0) {
    return retry_or_deny();          // lost the race, or not enough funds
}
// Note balance = balance - :amt, not balance = :staleValue - :amt.
PHP,
        'note' => 'Two rules, and this level breaks both: the compare-and-swap must be atomic, and arithmetic on a
            shared value must be expressed relative to the stored value rather than to one you read earlier.',
    ],
    'scenario' => '<strong>Scenario:</strong> a purchase endpoint with a version column and an explicit conflict
        check. The account holds 100 and each purchase costs 50.
        <br><strong>Goal:</strong> spend more than 100.',
    'model' => [
        'title' => 'The check that changes nothing',
        'html'  => '<pre class="lk-sinkline">A: read v=1 ── work ── check v==1 ok ──┐── write v=2, balance=50
B: read v=1 ── work ── check v==1 ok ──┘── write v=2, balance=50
                                          both passed, both wrote</pre>
        <p>Compare with the atomic form, where the database evaluates <code>version = 1</code> at the instant of the
        write. There, exactly one of A and B updates a row and the other gets a row count of zero.</p>',
    ],
    'why' => '<p>Both requests compared the version against the same unchanged value and both proceeded. The write
        that landed second then stored a balance computed from the original read, discarding the first debit as
        well - a lost update on top of a failed compare-and-swap.</p>
        <p>The version field is doing exactly what it was designed to do. It is being consulted at the wrong
        moment.</p>',
];

/* ------------------------------------------------------------------ 10 */
$defs[10] = [
    'code' => <<<'PHP'
// POST /api/store?op=buy
if ($s['balance'] < 50) { return deny(); }
process_purchase();                  // ~150 ms
$s['balance'] -= 50;  $s['credits'] += 1;   save($s);

// POST /api/store?op=refund
if ($s['credits'] < 1) { return deny(); }   // checks the credit COUNT ...
process_refund();                    // ~150 ms
$s['balance'] += 50;  $s['refunds'] += 1;   save($s);
//                                   ... but never how many refunds already ran
PHP,
    'vuln_lines' => [2, 3, 4, 6, 7, 8],
    'annotation' => 'Two independent windows. The buy path can be raced to obtain more credits than were paid for,
        and the refund path can be raced because it is validated against the credit count rather than against the
        refunds already issued.',
    'theory' => '<p>Individually, each of these races has a bounded payoff: the balance limits how far the buy race
        can go, and one credit only justifies one refund. Chained, they feed each other, and the account grows on
        every cycle.</p>
        <p>This is the practical reason to keep pulling on a race after the first anomaly. A finding of "the
        purchase limit can be exceeded by one" is a low-severity note. The same finding, combined with a refund path
        that validates against the wrong quantity, is unbounded value extraction - and the second half is invisible
        if you stop at the first.</p>
        <p>When you report a race, describe the reachable end state rather than the mechanism. "Two coupons applied"
        is a curiosity; "arbitrary account balance" is the finding.</p>',
    'fix' => [
        'bad' => <<<'PHP'
if ($credits < 1) { return deny(); }         // wrong quantity
refund();
$balance += 50; $refunds += 1;
PHP,
        'good' => <<<'PHP'
// Validate against the quantity that actually bounds the operation, and make
// the claim atomic in both paths.
$st = $db->prepare(
    'UPDATE orders SET refunded_amount = refunded_amount + :amt
      WHERE id = :id AND refunded_amount + :amt <= paid_amount'
);
$st->execute(['amt' => 50, 'id' => $orderId]);
if ($st->rowCount() === 0) {
    return deny('refund exceeds the amount paid');
}
// And ledger every movement, so the invariant (sum of entries == balance)
// can be checked independently of the code that maintains it.
PHP,
        'note' => 'A running invariant check - balance equals the sum of the ledger - turns a silent inconsistency
            into an alert. It does not prevent the race, but it stops it going unnoticed for months.',
    ],
    'scenario' => '<strong>Scenario:</strong> a store where credits cost 50 and refunds return 50. You start with a
        balance of 50.
        <br><strong>Goal:</strong> reach a balance above 200.',
    'model' => [
        'title' => 'Two windows, in order',
        'html'  => '<ol>
            <li><strong>Obtain a credit.</strong> Buying one legitimately costs exactly what a refund returns, so
                this step is not where the money comes from. Racing the buys gets you several credits off the same
                balance check, which is worth seeing but is not required.</li>
            <li><strong>Race the refunds.</strong> The refund is gated on <em>holding</em> a credit, and the check
                is separated from the consumption. Concurrent refunds all read the same credit and all pay out.</li>
            <li><strong>Repeat if needed.</strong> Each cycle needs one credit and returns as many refunds as you
                can fit inside the window.</li>
        </ol>
        <p>Reload between the two steps so you can see the state move. If a burst gains nothing, check that you
        were holding at least one credit when it started.</p>',
    ],
    'why' => '<p>Neither window alone gets you past the starting balance. The buy race produced credits that were
        never fully paid for, and the refund race converted each of those credits into balance more than once,
        because the refund check looked at the wrong quantity.</p>
        <p>That is the pattern worth remembering: races compose. The severity of a race condition is decided by what
        else it can be combined with, not by the size of the single anomaly you first observed.</p>',
];

    return $defs[$level] ?? [];
}
