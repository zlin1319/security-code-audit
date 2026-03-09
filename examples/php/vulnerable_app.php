<?php

$name = $_GET["name"];
$url = $_GET["url"];
$cmd = $_GET["cmd"];
$payload = $_POST["payload"];

$query = "SELECT * FROM users WHERE name = '" . $name . "'";
$db->query($query);

echo "<div>" . $name . "</div>";
system($_GET["cmd"]);
file_get_contents($_GET["url"]);
unserialize($_POST["payload"]);

$token = md5($name . rand());
$password = "demo-insecure-password";

echo $token;
