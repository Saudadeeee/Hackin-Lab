<?php
/**
 * Race Condition Lab · per-learner state and the deliberately unsafe helpers
 * the levels are built from.
 *
 * State lives in a JSON file per (session, level). PHP's own sessions are NOT
 * used for most levels, because session_start() takes an exclusive lock on the
 * session file and serialises every request from the same browser - which
 * silently fixes half the bugs this lab is trying to show. Level 6 turns that
 * behaviour into its own lesson.
 */

/** Identify the learner with a plain cookie. No locking, deliberately. */
function race_sid(): string
{
    if (!empty($_COOKIE['race_sid']) && preg_match('/^[a-f0-9]{16}$/', $_COOKIE['race_sid'])) {
        return $_COOKIE['race_sid'];
    }
    $sid = bin2hex(random_bytes(8));
    setcookie('race_sid', $sid, time() + 86400 * 7, '/');
    $_COOKIE['race_sid'] = $sid;
    return $sid;
}

function race_state_dir(): string
{
    $d = __DIR__ . '/state';
    if (!is_dir($d)) {
        @mkdir($d, 0777, true);
    }
    return $d;
}

function race_state_file(int $level, ?string $sid = null): string
{
    return race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '.json';
}

/**
 * Read state. Note the absence of any lock: two requests can both read the
 * same value before either writes, which is precisely the bug being taught.
 */
function race_read(int $level, array $default, ?string $sid = null): array
{
    $f = race_state_file($level, $sid);
    if (!is_file($f)) {
        return $default;
    }
    $d = json_decode((string)@file_get_contents($f), true);
    return is_array($d) ? $d + $default : $default;
}

function race_write(int $level, array $state, ?string $sid = null): void
{
    @file_put_contents(race_state_file($level, $sid), json_encode($state));
}

function race_reset(int $level, ?string $sid = null): void
{
    @unlink(race_state_file($level, $sid));
}

/**
 * The gap between check and use, made visible.
 *
 * Real applications do not sleep here - they do a template render, a log
 * write, a second query, a network call to a payment provider. The window is
 * the same shape; this just makes it wide enough to hit by hand.
 */
function race_work(int $ms = 120): void
{
    usleep($ms * 1000);
}

/** Append to a per-level request log so the trace can show interleaving. */
function race_log(int $level, string $line, ?string $sid = null): void
{
    $f = race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '.log';
    @file_put_contents(
        $f,
        sprintf("%.4f  pid=%-6d  %s\n", microtime(true), getmypid(), $line),
        FILE_APPEND
    );
}

function race_log_read(int $level, ?string $sid = null): array
{
    $f = race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '.log';
    if (!is_file($f)) {
        return [];
    }
    $lines = array_values(array_filter(explode("\n", (string)@file_get_contents($f))));
    return array_slice($lines, -40);
}

function race_log_clear(int $level, ?string $sid = null): void
{
    @unlink(race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '.log');
}

/**
 * Render the interleaving log as a trace block. Two requests that overlap show
 * up as two pids alternating - the visual signature of a race.
 */
function race_log_block(int $level, ?string $sid = null): string
{
    $lines = race_log_read($level, $sid);
    if (!$lines) {
        return '';
    }
    $first = null;
    $rows  = '';
    foreach ($lines as $l) {
        if (preg_match('/^([\d.]+)\s+pid=(\d+)\s+(.*)$/', $l, $m)) {
            $first ??= (float)$m[1];
            $rows .= '<tr><td>+' . number_format(((float)$m[1] - $first) * 1000, 1) . ' ms</td>'
                  . '<td>pid ' . $m[2] . '</td><td>' . lk_esc($m[3]) . '</td></tr>';
        }
    }
    return '<div class="lk-box"><h4><span class="lk-tag">INTERLEAVING</span>Server-side request log</h4>'
         . '<div class="lk-body"><table class="lk-kv">' . $rows . '</table>'
         . '<p class="text-muted" style="margin-top:0.5rem">Different pids interleaving between a read and its
            matching write is the signature to look for. If every request runs to completion before the next one
            starts, something is serialising them - find out what before assuming the bug is absent.</p></div></div>';
}

/* =========================================================================
 * The launcher: fires N requests in parallel from the browser
 * ===================================================================== */

/**
 * Render a parallel-request control. Requests go out with Promise.all, so they
 * leave the browser together and carry the learner's cookies.
 */
function race_launcher(string $endpoint, array $fields = [], int $default = 5, string $label = 'Fire parallel requests'): string
{
    static $scriptRendered = false;
    $id   = 'rl_' . bin2hex(random_bytes(3));
    $json = htmlspecialchars(json_encode($fields), ENT_QUOTES, 'UTF-8');

    ob_start(); ?>
    <div class="lk-box rl" id="<?= $id ?>" data-endpoint="<?= lk_esc($endpoint) ?>" data-fields="<?= $json ?>">
        <h4><span class="lk-tag">LAUNCHER</span><?= lk_esc($label) ?></h4>
        <div class="lk-body">
            <div class="rl-row">
                <label class="form-label" style="margin:0">requests</label>
                <input type="number" class="form-control rl-n" value="<?= $default ?>" min="2" max="40" style="width:6rem">
                <label class="form-label" style="margin:0">
                    <input type="checkbox" class="rl-warm" checked> warm the connections first
                </label>
                <button class="btn btn-primary rl-go" type="button">Send</button>
                <button class="btn btn-outline rl-reload" type="button">Reload state</button>
            </div>
            <div class="rl-out output-box" hidden></div>
            <p class="text-muted">Warming sends one throwaway request per connection so TCP and PHP are already
            started. Without it the first request pays setup costs the others do not, and the window closes before
            the rest arrive.</p>
        </div>
    </div>
    <?php
    if (!$scriptRendered) {
        $scriptRendered = true; ?>
        <style>
            .rl-row { display:flex; gap:0.6rem; align-items:center; flex-wrap:wrap; margin-bottom:0.6rem; }
            .rl-out { max-height: 16rem; overflow:auto; }
        </style>
        <script>
        document.addEventListener('click', async function (e) {
            const box = e.target.closest('.rl');
            if (!box) return;

            if (e.target.classList.contains('rl-reload')) { location.reload(); return; }
            if (!e.target.classList.contains('rl-go')) return;

            const n      = Math.max(2, Math.min(40, parseInt(box.querySelector('.rl-n').value, 10) || 5));
            const warm   = box.querySelector('.rl-warm').checked;
            const out    = box.querySelector('.rl-out');
            const url    = box.dataset.endpoint;
            const fields = JSON.parse(box.dataset.fields || '{}');

            const body = () => {
                const p = new URLSearchParams();
                for (const k in fields) p.append(k, fields[k]);
                return p;
            };

            out.hidden = false;
            out.textContent = 'warming...\n';

            if (warm) {
                await Promise.all(Array.from({length: n}, () =>
                    fetch(url + '?warm=1', {method: 'POST', body: body(), credentials: 'same-origin'})
                        .catch(() => {})));
            }

            out.textContent = 'sending ' + n + ' requests...\n';
            const t0 = performance.now();
            const results = await Promise.all(Array.from({length: n}, (_, i) =>
                fetch(url, {method: 'POST', body: body(), credentials: 'same-origin'})
                    .then(r => r.text())
                    .then(t => ({i, t: t.trim().slice(0, 200)}))
                    .catch(err => ({i, t: 'error: ' + err}))));
            const ms = (performance.now() - t0).toFixed(1);

            results.sort((a, b) => a.i - b.i);
            out.textContent = results.map(r => '#' + r.i + '  ' + r.t).join('\n')
                            + '\n\nall ' + n + ' completed in ' + ms + ' ms'
                            + '\nReload the page to see the resulting state and the interleaving log.';
        });
        </script>
    <?php }
    return ob_get_clean();
}

/* =========================================================================
 * Append-only ledgers
 * ---------------------------------------------------------------------
 * The CHECK in each level is deliberately racy. The EFFECT is recorded by
 * appending a line, which the OS performs atomically for small writes, so an
 * effect is never silently lost. That split matters: it is exactly how a real
 * application behaves when the write is `UPDATE t SET n = n + 1` (atomic) but
 * the decision to write came from a stale SELECT (not atomic).
 * ===================================================================== */

function race_ledger_file(int $level, string $name, ?string $sid = null): string
{
    return race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '-' . $name . '.log';
}

function race_ledger_add(int $level, string $name, string $line = '1', ?string $sid = null): void
{
    @file_put_contents(race_ledger_file($level, $name, $sid), $line . "\n", FILE_APPEND | LOCK_EX);
}

function race_ledger_rows(int $level, string $name, ?string $sid = null): array
{
    $f = race_ledger_file($level, $name, $sid);
    return is_file($f)
        ? array_values(array_filter(explode("\n", (string)@file_get_contents($f))))
        : [];
}

function race_ledger_count(int $level, string $name, ?string $sid = null): int
{
    return count(race_ledger_rows($level, $name, $sid));
}

/** Sum a numeric ledger. */
function race_ledger_sum(int $level, string $name, ?string $sid = null): float
{
    $t = 0.0;
    foreach (race_ledger_rows($level, $name, $sid) as $r) {
        $t += (float)$r;
    }
    return $t;
}

function race_ledger_clear_all(int $level, ?string $sid = null): void
{
    foreach (glob(race_state_dir() . '/' . ($sid ?? race_sid()) . '-l' . $level . '-*.log') ?: [] as $f) {
        @unlink($f);
    }
}

/** Largest number of arrivals falling inside any window of $span seconds. */
function race_best_window(array $rows, float $span): int
{
    $t = array_map('floatval', $rows);
    sort($t);
    $best = 0;
    $j    = 0;
    foreach ($t as $i => $start) {
        while ($j < count($t) && $t[$j] - $start <= $span) {
            $j++;
        }
        $best = max($best, $j - $i);
    }
    return $best;
}
