<?php

$servername = "127.0.0.1";
$username = "root";
$password = "";
$db = "demoapp";
$conn;

try
{
    $conn = new PDO("mysql:host=$servername;dbname=$db", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	
}
catch(PDOException $e)
{
	echo "Greska: " . $e->getMessage();
	$conn = null;
}
?>