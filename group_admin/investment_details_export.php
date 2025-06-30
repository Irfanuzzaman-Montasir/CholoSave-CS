<?php
session_start();
require('fpdf/fpdf.php');

if (!isset($_SESSION['investment_data'])) {
    echo "No data available for PDF export.";
    exit;
}

class InvestmentPDF extends FPDF {
    function Header() {
        // Add logo placeholder
        $this->Image('logo.png', 10, 6, 30);
        
        // Company name
        $this->SetFont('Arial', 'B', 20);
        $this->SetXY(70, 15);
        $this->Cell(0, 10, 'Investment Report', 0, 1, 'L');
        
        // Company details
        $this->SetFont('Arial', '', 10);
        $this->SetXY(70, 25);
        $this->Cell(0, 5, 'CHOLOSAVE.', 0, 1, 'L');
        $this->SetX(70);
        $this->Cell(0, 5, 'contact@company.com | +1234567890', 0, 1, 'L');
        
        // Date
        $this->SetXY(10, 45);
        $this->Cell(0, 5, 'Date: ' . date('d/m/Y'), 0, 1, 'R');
        
        // Decorative line
        $this->SetLineWidth(0.5);
        $this->Line(10, 55, 200, 55);
        $this->Ln(15);
    }
    
    function Footer() {
        $this->SetY(-15);
        $this->SetFont('Arial', 'I', 8);
        $this->Cell(0, 10, 'Page ' . $this->PageNo() . '/{nb}', 0, 0, 'C');
    }
}

$investments = $_SESSION['investment_data'];

// Calculate totals
$totalInvestment = 0;
$totalExpectedProfit = 0;
$totalActualReturns = 0;

foreach ($investments as $investment) {
    $totalInvestment += $investment['Investment Amount'];
    $totalExpectedProfit += $investment['Expected Profit'];
    $totalActualReturns += $investment['Return Amount'] ?? 0;
}

// Create PDF
$pdf = new InvestmentPDF();
$pdf->AliasNbPages();
$pdf->AddPage();

// Add summary box
$pdf->SetFillColor(240, 240, 240);
$pdf->SetFont('Arial', 'B', 12);
$pdf->Cell(0, 10, 'Investment Summary', 0, 1, 'L', true);
$pdf->SetFont('Arial', '', 10);
$pdf->Cell(95, 8, 'Total Investment: BDT ' . number_format($totalInvestment, 2), 1, 0, 'L');
$pdf->Cell(95, 8, 'Total Expected Profit: BDT ' . number_format($totalExpectedProfit, 2), 1, 1, 'L');
$pdf->Cell(95, 8, 'Total Actual Returns: BDT ' . number_format($totalActualReturns, 2), 1, 0, 'L');
$pdf->Cell(95, 8, 'Total Profit/Loss: BDT ' . number_format($totalActualReturns - $totalInvestment, 2), 1, 1, 'L');

$pdf->Ln(10);

// Table Header with styling
$pdf->SetFillColor(52, 73, 94);
$pdf->SetTextColor(255, 255, 255);
$pdf->SetFont('Arial', 'B', 10);
$pdf->Cell(30, 10, 'Amount', 1, 0, 'C', true);
$pdf->Cell(20, 10, 'Type', 1, 0, 'C', true);
$pdf->Cell(20, 10, 'Status', 1, 0, 'C', true);
$pdf->Cell(30, 10, 'Exp. Profit', 1, 0, 'C', true);
$pdf->Cell(30, 10, 'Return Amt', 1, 0, 'C', true);
$pdf->Cell(30, 10, 'Profit/Loss', 1, 0, 'C', true);
$pdf->Cell(30, 10, 'Return Date', 1, 1, 'C', true);

// Table Body with alternating colors
$pdf->SetTextColor(0, 0, 0);
$pdf->SetFont('Arial', '', 9);
$fill = false;

foreach ($investments as $investment) {
    $pdf->SetFillColor(245, 245, 245);
    
    // Investment Amount
    $pdf->Cell(30, 8, 'BDT ' . number_format($investment['Investment Amount'], 2), 1, 0, 'R', $fill);
    
    // Investment Type
    $pdf->Cell(20, 8, $investment['Type'], 1, 0, 'C', $fill);
    
    // Status with color coding
    $statusColor = match(strtolower($investment['status'])) {
        'completed' => array(46, 204, 113),
        'pending' => array(243, 156, 18),
        'active' => array(52, 152, 219),
        default => array(0, 0, 0)
    };
    $pdf->SetTextColor($statusColor[0], $statusColor[1], $statusColor[2]);
    $pdf->Cell(20, 8, ucfirst($investment['status']), 1, 0, 'C', $fill);
    
    // Reset text color
    $pdf->SetTextColor(0, 0, 0);
    
    // Expected Profit
    $pdf->Cell(30, 8, 'BDT ' . number_format($investment['Expected Profit'], 2), 1, 0, 'R', $fill);
    
    // Return Amount
    $pdf->Cell(30, 8, 
        $investment['Return Amount'] !== null 
        ? 'BDT ' . number_format($investment['Return Amount'], 2) 
        : '-', 
        1, 0, 'R', $fill
    );
    
    // Profit/Loss
    $profitLossColor = $investment['Profit/Loss'] > 0 ? array(0, 128, 0) : array(255, 0, 0);
    $pdf->SetTextColor($profitLossColor[0], $profitLossColor[1], $profitLossColor[2]);
    $pdf->Cell(30, 8, 
        $investment['Profit/Loss'] !== null 
        ? 'BDT ' . number_format($investment['Profit/Loss'], 2) 
        : '-', 
        1, 0, 'R', $fill
    );
    
    // Reset text color
    $pdf->SetTextColor(0, 0, 0);
    
    // Return Date
    $pdf->Cell(30, 8, 
        $investment['Return Date'] !== null 
        ? date('d-m-Y', strtotime($investment['Return Date'])) 
        : '-', 
        1, 1, 'C', $fill
    );
    
    $fill = !$fill;
}

// Add notes section
$pdf->Ln(10);
$pdf->SetFont('Arial', 'B', 11);
$pdf->Cell(0, 10, 'Notes:', 0, 1, 'L');
$pdf->SetFont('Arial', '', 10);
$pdf->MultiCell(0, 5, 'This is an official investment report. All amounts are in BDT (Bangladesh Taka). Profit/Loss calculations are based on Return Amount compared to Initial Investment.');

// Clear session data
unset($_SESSION['investment_data']);

// Output PDF
$pdf->Output('D', 'Investment_History.pdf');
exit;
?>