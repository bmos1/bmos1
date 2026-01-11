<?php 
$uploaddir = '/var/www/html/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
if(move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile))
    echo "Upload done.";
else
    echo "Upload error!";
?>
