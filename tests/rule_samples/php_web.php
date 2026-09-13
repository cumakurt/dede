<?php
// Static-only security regression samples; never execute this file.
function queries($db, $pdo) {
    $name = $_GET['name'];
    $query = "SELECT * FROM users WHERE name = '" . $name . "'";
    // ruleid: dede.php.web.sql-injection
    mysqli_query($db, $query);
    // ruleid: dede.php.web.sql-injection
    $pdo->prepare($query);
    // ok: dede.php.web.sql-injection
    $stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
    $stmt->execute([$name]);
}

function commands() {
    $command = $_POST['cmd'];
    // ruleid: dede.php.web.command-injection
    system($command);
    // ruleid: dede.php.web.command-injection
    shell_exec($command);
    // ok: dede.php.web.command-injection
    system('/usr/bin/uptime');
}

function evaluation() {
    $code = $_REQUEST['code'];
    // ruleid: dede.php.web.code-injection
    eval($code);
    // ok: dede.php.web.code-injection
    eval('return 1 + 2;');
}

function inclusion() {
    $path = $_GET['page'];
    // ruleid: dede.php.web.file-inclusion
    include $path;
    // ruleid: dede.php.web.file-inclusion
    require_once($path);
    // ok: dede.php.web.file-inclusion
    include '/srv/views/home.php';
}
