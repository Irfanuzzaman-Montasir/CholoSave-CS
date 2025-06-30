<?php
session_start();
require('fpdf/fpdf.php');

// Check if session data exists
if (!isset($_SESSION['transaction_id'], $_SESSION['total_amount'], $_SESSION['payment_method'], $_SESSION['transaction_date'])) {
    die("No transaction data found.");
}

// Retrieve session data
$transaction_id = $_SESSION['transaction_id'];
$total_amount = $_SESSION['total_amount'];
$payment_method = $_SESSION['payment_method'];
$transaction_date = $_SESSION['transaction_date'];

// Create PDF using FPDF
class PDF extends FPDF
{
    // Page header
    function Header()
    {
        // Logo
        $this->Image('logo.png', 10, 6, 30); // Optional: Add a logo
        $this->SetFont('Arial', 'B', 14);
        $this->Cell(0, 10, 'Payment Receipt', 0, 1, 'C');
        $this->SetFont('Arial', '', 12);
        $this->Cell(0, 10, 'Issued by [CholoSave]', 0, 1, 'C'); // Replace with your company name
        $this->Ln(10);
    }

    // Page footer
    function Footer()
    {
        $this->SetY(-30);
        $this->SetFont('Arial', 'I', 8);
        $this->Cell(0, 10, 'For any queries, contact us at support@example.com', 0, 1, 'C'); // Replace with actual support email
        $this->Cell(0, 10, 'Thank you for your business!', 0, 0, 'C');
    }
}

$pdf = new PDF();
$pdf->AddPage();
$pdf->SetFont('Arial', '', 12);

// Add transaction details with a border
$pdf->SetFillColor(230, 230, 230); // Light gray background for headers
$pdf->Cell(0, 10, 'Transaction Details', 1, 1, 'C', true);
$pdf->Ln(5);

$pdf->SetFont('Arial', '', 11);
$pdf->Cell(50, 10, 'Transaction ID:', 1, 0, 'L');
$pdf->Cell(0, 10, $transaction_id, 1, 1, 'L');

$pdf->Cell(50, 10, 'Date:', 1, 0, 'L');
$pdf->Cell(0, 10, $transaction_date, 1, 1, 'L');

$pdf->Cell(50, 10, 'Payment Method:', 1, 0, 'L');
$pdf->Cell(0, 10, $payment_method, 1, 1, 'L');

$pdf->Cell(50, 10, 'Total Amount:', 1, 0, 'L');
$pdf->Cell(0, 10, '$' . number_format($total_amount, 2), 1, 1, 'L'); // Ensure proper formatting of the amount

// Add thank-you message
$pdf->Ln(10);
$pdf->SetFont('Arial', 'B', 12);
$pdf->SetTextColor(0, 102, 204); // Set text color to blue
$pdf->Cell(0, 10, 'Thank you for choosing our services!', 0, 1, 'C');

// Add footer notes
$pdf->SetFont('Arial', 'I', 10);
$pdf->SetTextColor(0, 0, 0); // Reset text color to black
$pdf->Ln(10);
$pdf->MultiCell(0, 10, "This is a computer-generated receipt and does not require a signature.", 0, 'C');

// Output the PDF
$pdf->Output('D', 'receipt.pdf'); // 'D' forces download; 'I' displays in browser

// Optionally, clear session data after displaying it
unset($_SESSION['transaction_id'], $_SESSION['total_amount'], $_SESSION['payment_method'], $_SESSION['transaction_date']);
?>
