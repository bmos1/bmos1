<!DOCTYPE html>
<html> 
<body> 
<h1>Upload result</h1>

<?php 
$target_path = "uploads/"; 
$target_path = $target_path . basename($_FILES['file']['name']); 

echo "Source = " . $_FILES['file']['name'] . " <br /> \n"; 
echo "Path = " . $target_path . " <br /> \n"; 
echo "Size = " . $_FILES['file']['size'] . " <br /> \n\n"; 

if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) { 
echo "Success. The file " . basename( $_FILES['file']['name']) . " has been uploaded."; 
} else { 
echo "Error uploading the file failed, please try it again!"; 
} 
?>

</body> 
</html> 
