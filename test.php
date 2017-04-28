

<?php
$var = $_POST['var'];
mysql_query("SELECT * FROM sometable WHERE id = $var");

$a = htmlentities($_GET['a']);
$b = $_GET['b'];
$c = $_GET['c'];
$d = htmlentities($b);

echo ($a); // safe
echo (htmlentities($b)); // safe
echo ($c); // XSS vulnerability
echo ($d); // safe
echo (htmlentities($_GET['id']); // safe

?>