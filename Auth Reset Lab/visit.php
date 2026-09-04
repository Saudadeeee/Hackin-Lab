<?php
/**
 * Auth Reset Lab · the victim
 * ---------------------------------------------------------------------------
 * Two levels need somebody other than you to do something: level 3 needs the
 * administrator to open a message and click the link inside it, level 7 needs
 * the administrator to sign in. This endpoint is that person.
 *
 * The actions are real. "Open the reset mail" performs an actual HTTP GET on
 * whatever URL the message contains, so if the link names a host you control,
 * the request genuinely arrives there. "Log in" runs the application's own
 * login path, including the part of it that is wrong.
 *
 * The file is also loadable as a library: level pages call the two functions
 * directly so the result can be shown inline.
 */

require_once __DIR__ . '/helpers.php';

/**
 * The administrator opens the newest reset message and clicks the link.
 *
 * @return array{sent:bool, link:string, status:int, error:string, note:string}
 */
function ar_visit_open_reset_mail(int $level): array
{
    ar_ensure_level($level);
    $mail = ar_latest_mail($level, AR_ADMIN);

    if ($mail === null || empty($mail['link'])) {
        return ['sent' => false, 'link' => '', 'status' => 0, 'error' => '',
                'note' => 'There is no reset message in the administrator mailbox yet.'];
    }

    $res = ar_http_get((string)$mail['link']);
    return [
        'sent'   => true,
        'link'   => (string)$mail['link'],
        'status' => $res['status'],
        'error'  => $res['error'],
        'note'   => $res['ok']
            ? 'The mail client fetched the URL and got HTTP ' . $res['status'] . '.'
            : 'The mail client could not reach that host: ' . $res['error'],
    ];
}

/**
 * The administrator signs in.
 *
 * The vulnerable part is not the password check — it is that the application
 * keeps whatever session identifier the request arrived with instead of
 * issuing a fresh one once the privilege level changes.
 *
 * @return array{sid:string, adopted:bool, note:string}
 */
function ar_visit_login(int $level, string $sid): array
{
    ar_ensure_level($level);

    $sid     = preg_match('~^[A-Za-z0-9_.:-]{4,64}$~', $sid) ? $sid : '';
    $adopted = $sid !== '';

    if (!$adopted) {
        // No usable identifier in the request, so the app makes one up. This
        // is what the vulnerable code does when nobody plants a value.
        $sid = bin2hex(random_bytes(12));
    }

    // The session row is created (or reused) before authentication ...
    ar_session_touch($level, $sid);
    // ... and the same row is then marked authenticated. No regeneration.
    ar_session_authenticate($level, $sid, AR_ADMIN, 1, 'administrator signed in');

    return [
        'sid'     => $sid,
        'adopted' => $adopted,
        'note'    => $adopted
            ? 'The administrator arrived carrying sid=' . $sid . ' and the login kept it.'
            : 'No sid was supplied, so the application generated ' . $sid . ' — which you do not know.',
    ];
}

/* =========================================================================
 * Endpoint behaviour (skipped when the file is required by a level page)
 * ===================================================================== */

if (realpath(__FILE__) === realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? ''))) {
    $action = (string)($_REQUEST['action'] ?? '');
    $level  = (int)($_REQUEST['level'] ?? 0);
    if ($level < 1 || $level > 10) {
        $level = 3;
    }

    $body = '';
    switch ($action) {
        case 'open_reset_mail':
            $r = ar_visit_open_reset_mail($level);
            $body = '<div class="lk-box"><h4><span class="lk-tag">VICTIM</span>The administrator opened their mail</h4>'
                  . '<div class="lk-body"><table class="lk-kv">'
                  . '<tr><td>link in the message</td><td class="ar-mono">' . lk_esc($r['link']) . '</td></tr>'
                  . '<tr><td>result</td><td>' . lk_esc($r['note']) . '</td></tr>'
                  . '</table></div></div>';
            break;

        case 'login':
            $r = ar_visit_login($level, (string)($_REQUEST['sid'] ?? ''));
            $body = '<div class="lk-box"><h4><span class="lk-tag">VICTIM</span>The administrator signed in</h4>'
                  . '<div class="lk-body"><table class="lk-kv">'
                  . '<tr><td>session used</td><td class="ar-mono">' . lk_esc($r['sid']) . '</td></tr>'
                  . '<tr><td>result</td><td>' . lk_esc($r['note']) . '</td></tr>'
                  . '</table></div></div>';
            break;

        default:
            $body = '<div class="message info">This endpoint simulates somebody else using the application.'
                  . '<br><code>visit.php?action=open_reset_mail&amp;level=3</code> &mdash; the administrator opens the newest reset message and clicks the link.'
                  . '<br><code>visit.php?action=login&amp;level=7&amp;sid=&lt;value&gt;</code> &mdash; the administrator signs in, arriving with that session id.'
                  . '</div>';
    }

    $body .= '<div class="ar-toolbar"><a class="btn btn-outline" href="level' . $level . '.php">Back to level ' . $level . ' &rarr;</a></div>';
    ar_shell('Victim simulator', 'Somebody else uses the application', $body, $level);
}
