<?php
// Database connection
$host = $_ENV['DB_HOST'] ?? 'db';
$user = $_ENV['DB_USER'] ?? 'webapp'; 
$pass = $_ENV['DB_PASS'] ?? 'webapp123';
$dbname = $_ENV['DB_NAME'] ?? 'sqli_lab';

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Challenge Labs - SQL Injection Training</title>
    <link rel="stylesheet" href="css/styles.css">

</head>
<body>
    <div class="container">
        <div class="header">
            <h1> Login Challenge Labs</h1>
            <p>Master SQL injection through realistic login forms - 16 levels of increasing difficulty</p>
        </div>
        
        <div class="level-grid">
            <div class="level-card">
                <h3>Level 1 - Basic Login</h3>
                <p>Simple login form with error messages. Perfect for beginners to understand SQL injection.</p>
                <a href="level1.php">Start Level 1</a>
            </div>
            
            <div class="level-card">
                <h3>Level 2 - Union Login</h3>
                <p>Login form vulnerable to UNION-based attacks. Extract user data through login bypass.</p>
                <a href="level2.php">Start Level 2</a>
            </div>
            
            <div class="level-card">
                <h3>Level 3 - Stacked Query Login</h3>
                <p>Advanced login that allows multiple SQL statements. Execute system commands.</p>
                <a href="level3.php">Start Level 3</a>
            </div>
            
            <div class="level-card">
                <h3>Level 4 - WAF Protected Login</h3>
                <p>Login guarded by a keyword blocklist plus quote/semicolon stripping. Evade the filter with case and keyword tricks.</p>
                <a href="level4.php">Start Level 4</a>
            </div>
            
            <div class="level-card">
                <h3>Level 5 - Boolean Blind Login</h3>
                <p>No errors, no data output — only success vs. "Access denied". Infer the password one bit at a time.</p>
                <a href="level5.php">Start Level 5</a>
            </div>
            
            <div class="level-card">
                <h3>Level 6 - Time-Based Blind Login</h3>
                <p>The result is hidden but the query time is reported. Use SLEEP() as a timing oracle to extract data.</p>
                <a href="level6.php">Start Level 6</a>
            </div>
            
            <div class="level-card">
                <h3>Level 7 - File Write (OUTFILE) Login</h3>
                <p>Out-of-band exfiltration. Use INTO OUTFILE to dump query results to the filesystem and read them back.</p>
                <a href="level7.php">Start Level 7</a>
            </div>
            
            <div class="level-card">
                <h3>Level 8 - Second Order Login</h3>
                <p>Registration stores your input; a later login reuses it in a second query. Persist the payload, then trigger it.</p>
                <a href="level8.php">Start Level 8</a>
            </div>
            
            <div class="level-card">
                <h3>Level 9 - XPath / XML Login</h3>
                <p>Login backed by an XML user store queried via XPath. Break out of the predicate to bypass the role check.</p>
                <a href="level9.php">Start Level 9</a>
            </div>
            
            <div class="level-card">
                <h3>Level 10 - Registration Login</h3>
                <p>Registration form with INSERT injection. Create accounts to bypass authentication.</p>
                <a href="level10.php">Start Level 10</a>
            </div>
            
            <div class="level-card">
                <h3>Level 11 - Profile Update Login</h3>
                <p>Login with profile update functionality. Exploit UPDATE statement vulnerabilities.</p>
                <a href="level11.php">Start Level 11</a>
            </div>
            
            <div class="level-card">
                <h3>Level 12 - JSON API Login</h3>
                <p>Modern API-based login using a JSON body. Fields are parsed straight into SQL — inject through JSON.</p>
                <a href="level12.php">Start Level 12</a>
            </div>
            
            <div class="level-card">
                <h3>Level 13 - Comment Filtered Login</h3>
                <p>Login that strips SQL comment characters. Craft comment-less payloads to bypass keyword detection.</p>
                <a href="level13.php">Start Level 13</a>
            </div>
            
            <div class="level-card">
                <h3>Level 14 - Encoded Login</h3>
                <p>Input is URL/HTML-decoded before filtering. Master encoding combinations to slip keywords past the filter.</p>
                <a href="level14.php">Start Level 14</a>
            </div>
            
            <div class="level-card">
                <h3>Level 15 - Space Filtered Login</h3>
                <p>Literal spaces are blocked. Use comments, tabs, or newlines as whitespace to keep your query valid.</p>
                <a href="level15.php">Start Level 15</a>
            </div>
            
            <div class="level-card">
                <h3>Level 16 - Advanced WAF (Final Boss)</h3>
                <p>Five independent filter layers at once — comments, keywords, special chars, logical operators, and whitespace.</p>
                <a href="level16.php">Start Level 16</a>
            </div>
        </div>
        
        <div class="navigation">
            <a href="sandbox.php"> SQL Sandbox</a>
            <a href="submit.php?level=1">&rarr; Submit Flags</a>
        </div>
    </div>
</body>
</html>

<?php
$conn->close();
?>


