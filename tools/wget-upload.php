<!DOCTYPE html>
<html>
<body>
<h1>Upload result</h1>

<?php

// Read raw POST body
$data = file_get_contents("php://input");

// Get filename from query string: ?filename=example.bin
if (!isset($_GET['filename']) || $_GET['filename'] === '') {
  die("No filename provided\n");
}
$filename = basename($_GET['filename']);

// security: strip paths
$target = "uploads/" . $filename;

// Save file
$bytes = file_put_contents($target, $data);

header("Content-Type: text/plain");
if ($bytes === false) {
  echo "Error. Failed to write file!\n";
} else
{
  echo "Source = $filename\n";
  echo "Path = $target\n";
  echo "Size = " . $bytes . "\n";
  echo "Success. The file $filename has been uploaded.\n";
}

?>

</body>
</html>
