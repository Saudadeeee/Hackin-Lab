<?php
require_once __DIR__ . '/helpers.php';
html_open('IDOR Lab — Home');
?>
<div class="header">
    <div>
        <h1>IDOR Lab — Insecure Direct Object Reference</h1>
        <p>White-Box Access Control Challenge Lab &mdash; 10 Levels</p>
    </div>
    <div style="display:flex;gap:0.5rem;align-items:center;">
        <a href="submit.php" class="submit-btn">Submit Flag</a>
    </div>
</div>

<div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;margin-bottom:1.5rem;">
    <h2 style="margin-bottom:0.75rem;font-size:1.1rem;">About This Lab</h2>
    <p style="color:var(--text-muted);font-size:0.9rem;margin-bottom:0.75rem;">
        This lab focuses on <strong style="color:var(--text);">Insecure Direct Object Reference (IDOR)</strong> and
        <strong style="color:var(--text);">Broken Access Control</strong> vulnerabilities, ranked #1 in the OWASP Top 10.
        All challenges are <strong style="color:var(--primary);">white-box</strong> — the vulnerable PHP source code is
        shown prominently on each level page, with the vulnerable line highlighted in red.
    </p>
    <p style="color:var(--text-muted);font-size:0.9rem;margin-bottom:0.75rem;">
        <strong style="color:var(--text);">Context:</strong> In most levels, you are simulated as logged-in user
        <strong style="color:#6ee7b7;">Alice (ID: 1)</strong>. Your goal is to access data belonging to other users
        by manipulating object references, parameters, cookies, or tokens.
    </p>
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:0.75rem;">
        <span class="badge badge-easy">Easy (Levels 1–3)</span>
        <span class="badge badge-medium">Medium (Levels 4–6)</span>
        <span class="badge badge-hard">Hard (Levels 7–9)</span>
        <span class="badge badge-expert">Expert (Level 10)</span>
    </div>
</div>

<div class="level-grid">

    <div class="level-card">
        <span class="badge badge-easy">Easy</span>
        <h3>Level 1 — Basic IDOR</h3>
        <p>Fetch any document by manipulating the numeric <code>id</code> parameter. No ownership check exists on the server.</p>
        <a href="level1.php">Start Level 1</a>
    </div>

    <div class="level-card">
        <span class="badge badge-easy">Easy</span>
        <h3>Level 2 — IDOR File Download</h3>
        <p>Download another user's uploaded file by guessing or enumerating the <code>filename</code> parameter.</p>
        <a href="level2.php">Start Level 2</a>
    </div>

    <div class="level-card">
        <span class="badge badge-easy">Easy</span>
        <h3>Level 3 — Hidden Form Field Tampering</h3>
        <p>A profile form contains a <code>user_id</code> field. The server trusts it completely. Change it to access another user's profile.</p>
        <a href="level3.php">Start Level 3</a>
    </div>

    <div class="level-card">
        <span class="badge badge-medium">Medium</span>
        <h3>Level 4 — Horizontal Privilege Escalation</h3>
        <p>Read messages not addressed to you by enumerating <code>msg_id</code> — the server never checks <code>recipient_id</code>.</p>
        <a href="level4.php">Start Level 4</a>
    </div>

    <div class="level-card">
        <span class="badge badge-medium">Medium</span>
        <h3>Level 5 — Mass Assignment</h3>
        <p>The profile update endpoint binds all POST parameters including sensitive ones. Inject <code>role=admin</code> to escalate privileges.</p>
        <a href="level5.php">Start Level 5</a>
    </div>

    <div class="level-card">
        <span class="badge badge-medium">Medium</span>
        <h3>Level 6 — Cookie Role Forgery</h3>
        <p>The application stores your role in a client-side cookie with no signature. Forge the cookie to gain admin access.</p>
        <a href="level6.php">Start Level 6</a>
    </div>

    <div class="level-card">
        <span class="badge badge-hard">Hard</span>
        <h3>Level 7 — API IDOR</h3>
        <p>A REST API validates your API key but not which user's data you are requesting. Use your key to fetch admin's data.</p>
        <a href="level7.php">Start Level 7</a>
    </div>

    <div class="level-card">
        <span class="badge badge-hard">Hard</span>
        <h3>Level 8 — Predictable Reset Token</h3>
        <p>Password reset tokens are generated using a predictable algorithm. Compute the admin's reset token and exploit it.</p>
        <a href="level8.php">Start Level 8</a>
    </div>

    <div class="level-card">
        <span class="badge badge-hard">Hard</span>
        <h3>Level 9 — JWT No Signature Verification</h3>
        <p>The application uses JWT tokens but never verifies the signature. Forge a token with <code>role: admin</code> to gain access.</p>
        <a href="level9.php">Start Level 9</a>
    </div>

    <div class="level-card">
        <span class="badge badge-expert">Expert</span>
        <h3>Level 10 — Race Condition (TOCTOU)</h3>
        <p>A Check-Time-of-Use / Time-of-Check race condition allows a second user to claim a reward created for another user.</p>
        <a href="level10.php">Start Level 10</a>
    </div>

</div>

<div style="margin-top:1.5rem;padding:1rem;background:var(--surface);border:1px solid var(--border);border-radius:10px;font-size:0.85rem;color:var(--text-muted);">
    <strong style="color:var(--text);">Disclaimer:</strong> This lab is intentionally vulnerable for educational purposes.
    All challenges run in an isolated Docker container. Do not deploy in a production environment.
</div>

<?php html_close(); ?>
