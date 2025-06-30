<?php
// Sample PHP script to generate a receipt file
$filename = "receipt-" . time() . ".pdf"; // or any unique filename
// Example content to save to the file (here, you might generate dynamic content based on the transaction)
$content = "Receipt\nTransaction ID: #2024-0113-789\nDate: Jan 13, 2025\nPayment Method: ****-4589\n";

// Save the receipt as a PDF or text file (here we simulate a simple text file)
file_put_contents("path/to/receipts/$filename", $content);

// Serve the file to the user for download
header('Content-Type: application/pdf'); // Adjust the MIME type if you're generating a PDF
header('Content-Disposition: attachment; filename="' . $filename . '"');
readfile("path/to/receipts/$filename");
exit;
?>
