<?php

require_once("mauth.php");

$param = [
    "dsn" => "sqlite:users.db",
    "table" => "users",
    "usernamecol" => "username",
    "passwordcol" => "password",
    "db_fields" => "*",
    "saltdsn" => "sqlite:salts.db",
    "salttable" => "salts",
    "saltcol" => "salt"];

$auth = new Auth("DB",$param,"");
$pdo1 = new PDO('sqlite:users.db');
$pdo2 = new PDO('sqlite:salts.db');

echo <<<FORM
<form method="post" action="setup.php">
    RESET(DROP/CREATE TABLE)
    <input type="hidden" name="mode" value="drop">
    <input type="submit">
</form>
FORM;

if(isset($_POST["mode"]) && $_POST["mode"]=="drop"){
    $stmt1 = $pdo1->prepare('DROP TABLE IF EXISTS users;');
    $stmt1->execute();
    $stmt1 = $pdo1->prepare('CREATE TABLE users(username,password);');
    $stmt1->execute();
    $stmt2 = $pdo2->prepare('DROP TABLE IF EXISTS salts;');
    $stmt2->execute();
    $stmt2 = $pdo2->prepare('CREATE TABLE salts(username,salt);');
    $stmt2->execute();
}

echo <<<FORM
<form method="post" action="setup.php">
    addUser(
    <input type="hidden" name="mode" value="addUser">
    <input type="text" name="username">
    <input type="password" name="password">)
    <input type="submit">
</form>
FORM;

if(isset($_POST["mode"]) && $_POST["mode"]=="addUser"){
    $auth->addUser($_POST["username"],$_POST["username"]);
}

if($auth){
    print_r($auth->listUsers());
}

?>
<p><a href="index.php">index.php</a></p>
