/*
   AI-DTCTM | Webshell Detection Rules
   ═══════════════════════════════════════════════════════════════
   Webshells are scripts uploaded to compromised servers that give
   attackers remote command execution through a web browser.
   
   Common in PHP, ASP, JSP. Critical to detect during file upload scans.
*/

rule Webshell_PHP_Eval
{
    meta:
        author      = "AI-DTCTM"
        description = "PHP eval() on user input = webshell"
        severity    = "critical"
        category    = "webshell"

    strings:
        $php    = "<?php"
        $eval1  = "eval($_POST"  nocase
        $eval2  = "eval($_GET"   nocase
        $eval3  = "eval($_REQUEST" nocase
        $eval4  = "eval($_COOKIE" nocase
        $assert = "assert($_POST" nocase

    condition:
        $php and any of ($eval*, $assert)
}


rule Webshell_PHP_Generic
{
    meta:
        author      = "AI-DTCTM"
        description = "Generic PHP webshell markers"
        severity    = "high"
        category    = "webshell"

    strings:
        $php = "<?php"
        $s1  = "system($_"        nocase
        $s2  = "exec($_"          nocase
        $s3  = "shell_exec($_"    nocase
        $s4  = "passthru($_"      nocase
        $s5  = "proc_open($_"     nocase
        $s6  = "popen($_"         nocase

    condition:
        $php and any of ($s*)
}


rule Webshell_China_Chopper
{
    meta:
        author      = "AI-DTCTM"
        description = "China Chopper tiny webshell (20 bytes)"
        severity    = "critical"
        category    = "webshell"
        family      = "ChinaChopper"

    strings:
        $a = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" nocase
        $b = "<?php @eval($_POST["                                  nocase
        $c = "<%@Page Language=\"C#\"%><%eval(Request.Item["       nocase

    condition:
        any of them
}


rule Webshell_JSP_Common
{
    meta:
        author      = "AI-DTCTM"
        description = "JSP webshell patterns"
        severity    = "critical"
        category    = "webshell"

    strings:
        $s1 = "Runtime.getRuntime().exec(request.getParameter"
        $s2 = "ProcessBuilder(request.getParameter"
        $s3 = "<%= Runtime.getRuntime().exec"

    condition:
        any of them
}


rule Webshell_ASP_Common
{
    meta:
        author      = "AI-DTCTM"
        description = "Classic ASP webshell patterns"
        severity    = "critical"
        category    = "webshell"

    strings:
        $s1 = "WScript.Shell"  nocase
        $s2 = "Server.CreateObject" nocase
        $s3 = ".Exec(Request"  nocase
        $s4 = "Execute Request" nocase

    condition:
        2 of them
}


rule Webshell_Obfuscated_Function_Calls
{
    meta:
        author      = "AI-DTCTM"
        description = "Dynamic function calls used to hide bad intent"
        severity    = "medium"
        category    = "webshell"

    strings:
        $a = "$_POST[0]($_POST[1])"
        $b = "${$a}($b)"
        $c = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/

    condition:
        any of them
}
