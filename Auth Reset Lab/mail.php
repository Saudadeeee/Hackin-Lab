<?php
/**
 * Auth Reset Lab · the fake mailer
 * ---------------------------------------------------------------------------
 * Nothing leaves the container. "Sending" a message writes a row into the mail
 * table; mailbox.php renders the rows the learner is entitled to read, which is
 * exactly one mailbox: their own.
 *
 * The link builder lives here too, because the way a reset link is assembled is
 * itself a security decision (level 3).
 */

require_once __DIR__ . '/db.php';

/**
 * The canonical, configured origin of the application. A correct reset mailer
 * uses this constant and never looks at the request.
 */
const AR_CANONICAL_ORIGIN = 'http://localhost';

/**
 * The vulnerable link builder used by level 3.
 *
 * The host comes from the request. Behind a reverse proxy an application often
 * prefers X-Forwarded-Host, which is set by anyone who can reach the origin.
 */
function ar_reset_link_from_request(string $token, string $path = '/reset.php'): string
{
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? ($_SERVER['HTTP_HOST'] ?? 'localhost');
    return 'http://' . $host . $path . '?token=' . $token;
}

/** The safe link builder every other level uses. */
function ar_reset_link(string $token, string $path = '/reset.php'): string
{
    return AR_CANONICAL_ORIGIN . $path . '?token=' . $token;
}

/**
 * Deliver a reset message.
 *
 * @return int the mail row id
 */
function ar_send_reset_mail(int $level, string $to, string $token, string $link): int
{
    $body = "Someone asked to reset the password for $to.\n\n"
          . "Use the link below within 15 minutes:\n\n  $link\n\n"
          . "Token: $token\n\n"
          . "If this was not you, no action is required.";
    return ar_mail_insert($level, $to, 'Reset your Hackin-Lab password', $body, $link);
}

/** Deliver a one-time code. */
function ar_send_otp_mail(int $level, string $to, string $code): int
{
    $body = "Your Hackin-Lab verification code is:\n\n  $code\n\n"
          . "The code is six digits and is valid for the current recovery attempt.";
    return ar_mail_insert($level, $to, 'Your verification code', $body, null);
}

/**
 * The only mailbox a learner may read: their own.
 *
 * mailbox.php never accepts an address from the request. If a level's exploit
 * causes the administrator's mail to be delivered somewhere else (level 3),
 * it arrives at collector.php, not here.
 */
function ar_mailbox(int $level, string $owner = AR_GUEST, int $limit = 30): array
{
    $st = ar_db()->prepare('SELECT * FROM mail WHERE level = ? AND to_email = ? ORDER BY id DESC LIMIT ?');
    $st->bindValue(1, $level, PDO::PARAM_INT);
    $st->bindValue(2, $owner, PDO::PARAM_STR);
    $st->bindValue(3, $limit, PDO::PARAM_INT);
    $st->execute();
    return $st->fetchAll();
}

/** The newest message delivered to any address — used by the victim simulator. */
function ar_latest_mail(int $level, string $to): ?array
{
    $st = ar_db()->prepare('SELECT * FROM mail WHERE level = ? AND to_email = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$level, $to]);
    $row = $st->fetch();
    return $row ?: null;
}

/**
 * A plain HTTP GET, used when a simulated victim clicks a link in a message.
 * The request is real: whatever host the link names is resolved and contacted.
 *
 * @return array{ok:bool, status:int, body:string, error:string}
 */
function ar_http_get(string $url, int $timeout = 5): array
{
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if ($scheme !== 'http' && $scheme !== 'https') {
        return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'unsupported scheme'];
    }

    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'timeout'       => $timeout,
        'ignore_errors' => true,
        'header'        => "User-Agent: HackinLab-MailClient/1.0\r\nConnection: close\r\n",
    ]]);

    $body   = @file_get_contents($url, false, $ctx);
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('~\s(\d{3})\s~', $http_response_header[0], $m)) {
        $status = (int)$m[1];
    }

    return [
        'ok'     => $body !== false,
        'status' => $status,
        'body'   => (string)$body,
        'error'  => $body === false ? 'request failed (host unreachable, refused, or timed out)' : '',
    ];
}
