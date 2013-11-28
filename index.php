<?php

/**
 * sample page for mauth
 *
 *
 */

require_once("mauth.php");
//require_once("Auth.php");

$param = [
    "dsn" => "sqlite:users.db",
    "table" => "users",
    "usernamecol" => "username",
    "passwordcol" => "password",
    "db_fields" => "*",
    "saltdsn" => "sqlite:salts.db",
    "salttable" => "salts",
    "saltcol" => "salt"
];

function loginFunction(){
    echo <<<FORM
    <form method="post" action="index.php">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit">
    </form>
FORM;
}

function loginCallback(){
    echo "loginCallback";
}

function loginFailedCallback(){
    echo "loginFailedCallback";
}

$auth = new Auth("DB",$param,"loginFunction");
$auth->setLoginCallback("loginCallback");
$auth->setFailedLoginCallback("loginFailedCallback");

$auth->start();

// logout
// header()を使うため、HTML出力前に実施
if(isset($_GET["mode"])){
    if("logout"==$_GET["mode"]){
        $auth->logout();
        header("Location: ".$_SERVER['PHP_SELF']);
    }
}

if($auth->checkAuth()){
    echo "<p>authorized</p>\n";
    echo "<p>authorized:".$auth->getUsername()."</p>\n";
    echo '<p><a href="index.php?mode=logout">logout</a></p>';
}else{
    echo "<p>not authorized</p>\n";
}

?>
<p><a href="setup.php">setup</a></p>