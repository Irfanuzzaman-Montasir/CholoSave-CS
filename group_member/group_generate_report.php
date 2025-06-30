<?php
session_start();
require('fpdf/fpdf.php');
require('db.php');

$userId = $_SESSION['user_id']; 
$groupId = $_SESSION['group_id']; 

// [All your existing queries remain exactly the same]
$groupQuery = "
    SELECT
        g.group_name AS GroupName,
        u.name AS AdminName,
        (SELECT COUNT(*) FROM group_membership gm WHERE gm.group_id = g.group_id AND gm.status = 'approved') AS TotalMembers,
        g.dps_type AS DPSType,
        g.time_period AS TimePeriod,
        g.amount AS InstallmentAmount,
        DATE_FORMAT(g.start_date, '%d %M, %Y') AS StartDate,
        g.goal_amount AS GoalAmount,
        g.emergency_fund AS EmergencyFund,
        (SELECT COUNT(*) FROM loan_request l WHERE l.group_id = g.group_id AND l.status = 'approved') AS TotalLoansApproved,
        (SELECT SUM(s.amount) FROM savings s WHERE s.group_id = g.group_id) AS TotalSavings,
        (SELECT SUM(w.amount) FROM withdrawal w WHERE w.group_id = g.group_id AND w.status = 'approved') AS TotalWithdrawal,
        (SELECT SUM(i.amount) FROM investments i WHERE i.group_id = g.group_id) AS TotalInvestments,
        (SELECT SUM(ir.amount) FROM investment_returns ir JOIN investments i ON ir.investment_id = i.investment_id WHERE i.group_id = g.group_id) AS TotalReturns,
        ((SELECT SUM(ir.amount) FROM investment_returns ir JOIN investments i ON ir.investment_id = i.investment_id WHERE i.group_id = g.group_id) - (SELECT SUM(i.amount) FROM investments i WHERE i.group_id = g.group_id)) AS Profit
    FROM
        my_group g
    JOIN
        users u ON g.group_admin_id = u.id
    WHERE
        g.group_id = $groupId";

$groupResult = $conn->query($groupQuery);
$groupData = $groupResult->fetch_assoc();

// [Keep all other existing queries exactly the same]
$transactionsQuery = "
    SELECT
        t.amount,
        t.transaction_id,
        t.payment_method,
        DATE_FORMAT(t.payment_time, '%d %M, %Y') AS PaymentTime
    FROM
        transaction_info t
    WHERE
        t.user_id = $userId AND t.group_id = $groupId
    ORDER BY
        t.payment_time DESC
    LIMIT 5";

$transactionsResult = $conn->query($transactionsQuery);

$loansQuery = "
    SELECT
        l.amount,
        DATE_FORMAT(l.approve_date, '%d %M, %Y') AS ApproveDate
    FROM
        loan_request l
    WHERE
        l.user_id = $userId AND l.group_id = $groupId AND l.status = 'approved'
    ORDER BY
        l.approve_date DESC
    LIMIT 5";

$loansResult = $conn->query($loansQuery);

$withdrawalsQuery = "
    SELECT
        w.amount,
        DATE_FORMAT(w.approve_date, '%d %M, %Y') AS ApproveDate
    FROM
        withdrawal w
    WHERE
        w.user_id = $userId AND w.group_id = $groupId AND w.status = 'approved'
    ORDER BY
        w.approve_date DESC
    LIMIT 5";

$withdrawalsResult = $conn->query($withdrawalsQuery);

$memberQuery = "
    SELECT
        u.name AS MemberName,
        u.phone_number AS Phone,
        u.email AS Email,
        DATE_FORMAT(gm.join_date, '%d %M, %Y') AS JoinDate,
        CASE
            WHEN gm.is_admin = 1 THEN 'Admin'
            ELSE 'Member'
        END AS Role,
        COALESCE((SELECT SUM(s.amount) FROM savings s WHERE s.user_id = u.id AND s.group_id = gm.group_id), 0) AS TotalSavings,
        COALESCE((SELECT SUM(l.amount) FROM loan_request l WHERE l.user_id = u.id AND l.group_id = gm.group_id AND l.status = 'approved'), 0) AS TotalLoans,
        COALESCE((SELECT SUM(w.amount) FROM withdrawal w WHERE w.user_id = u.id AND w.group_id = gm.group_id AND w.status = 'approved'), 0) AS TotalWithdrawals
    FROM
        group_membership gm
    JOIN
        users u ON gm.user_id = u.id
    WHERE
        gm.group_id = $groupId AND gm.user_id = $userId";

$memberResult = $conn->query($memberQuery);
$memberData = $memberResult->fetch_assoc();

class PDF extends FPDF {
    function Header() {
        // Logo (you can add your logo here)
        $this->Image('logo.png', 10, 6, 30);
        
        // Report Title
        $this->SetFont('Arial', 'B', 20);
        $this->SetTextColor(44, 62, 80);
        $this->Cell(0, 20, 'Financial Report', 0, 1, 'C');
        $this->SetDrawColor(44, 62, 80);
        $this->Line(10, 28, 200, 28);
        $this->Ln(10);
    }

    function Footer() {
        $this->SetY(-15);
        $this->SetFont('Arial', 'I', 8);
        $this->SetTextColor(128);
        $this->Cell(0, 10, 'Page ' . $this->PageNo() . '/{nb}', 0, 0, 'C');
    }

    function SectionTitle($title) {
        $this->SetFont('Arial', 'B', 16);
        $this->SetFillColor(44, 62, 80);
        $this->SetTextColor(255);
        $this->Cell(0, 10, ' ' . $title, 0, 1, 'L', true);
        $this->Ln(5);
    }

    function DataRow($label, $value) {
        $this->SetFont('Arial', 'B', 11);
        $this->SetTextColor(44, 62, 80);
        $this->Cell(60, 8, $label, 0);
        $this->SetFont('Arial', '', 11);
        $this->Cell(0, 8, $value, 0);
        $this->Ln();
    }

    function TableHeader($headers, $widths) {
        $this->SetFont('Arial', 'B', 11);
        $this->SetFillColor(236, 240, 241);
        $this->SetTextColor(44, 62, 80);
        foreach($headers as $i => $header) {
            $this->Cell($widths[$i], 10, $header, 1, 0, 'C', true);
        }
        $this->Ln();
    }

    function TableRow($data, $widths) {
        $this->SetFont('Arial', '', 10);
        $this->SetTextColor(44, 62, 80);
        foreach($data as $i => $value) {
            $this->Cell($widths[$i], 8, $value, 1, 0, 'C');
        }
        $this->Ln();
    }
}

// Initialize PDF
$pdf = new PDF();
$pdf->AliasNbPages();
$pdf->AddPage();

// Group Overview Section
$pdf->SectionTitle('Group Overview');
$pdf->DataRow('Group Name:', $groupData['GroupName']);
$pdf->DataRow('Admin Name:', $groupData['AdminName']);
$pdf->DataRow('Total Members:', $groupData['TotalMembers']);
$pdf->DataRow('DPS Type:', $groupData['DPSType']);
$pdf->DataRow('Time Period:', $groupData['TimePeriod']);
$pdf->DataRow('Installment Amount:', number_format($groupData['InstallmentAmount'], 2));
$pdf->DataRow('Start Date:', $groupData['StartDate']);
$pdf->Ln(5);

// Financial Summary Section
$pdf->SectionTitle('Financial Summary');
$pdf->DataRow('Total Savings:', number_format($groupData['TotalSavings'], 2));
$pdf->DataRow('Total Investments:', number_format($groupData['TotalInvestments'], 2));
$pdf->DataRow('Total Returns:', number_format($groupData['TotalReturns'], 2));
$pdf->DataRow('Net Profit:', number_format($groupData['Profit'], 2));
$pdf->DataRow('Emergency Fund:', number_format($groupData['EmergencyFund'], 2));
$pdf->Ln(5);

// Member Information Section
$pdf->AddPage();
$pdf->SectionTitle('Member Information');
$pdf->DataRow('Member Name:', $memberData['MemberName']);
$pdf->DataRow('Role:', $memberData['Role']);
$pdf->DataRow('Join Date:', $memberData['JoinDate']);
$pdf->DataRow('Total Savings:', number_format($memberData['TotalSavings'], 2));
$pdf->DataRow('Total Loans:', number_format($memberData['TotalLoans'], 2));
$pdf->DataRow('Total Withdrawals:', number_format($memberData['TotalWithdrawals'], 2));
$pdf->Ln(5);

// Recent Transactions Section
$pdf->SectionTitle('Recent Transactions');
$transactionHeaders = array('Transaction ID', 'Amount', 'Payment Method', 'Date');
$transactionWidths = array(40, 40, 50, 60);
$pdf->TableHeader($transactionHeaders, $transactionWidths);

while ($transaction = $transactionsResult->fetch_assoc()) {
    $pdf->TableRow(array(
        $transaction['transaction_id'],
        number_format($transaction['amount'], 2),
        $transaction['payment_method'],
        $transaction['PaymentTime']
    ), $transactionWidths);
}
$pdf->Ln(10);

// Recent Loans Section
$pdf->SectionTitle('Recent Loans');
$loanHeaders = array('Amount', 'Approve Date');
$loanWidths = array(95, 95);
$pdf->TableHeader($loanHeaders, $loanWidths);

while ($loan = $loansResult->fetch_assoc()) {
    $pdf->TableRow(array(
        number_format($loan['amount'], 2),
        $loan['ApproveDate']
    ), $loanWidths);
}
$pdf->Ln(10);

// Recent Withdrawals Section
$pdf->SectionTitle('Recent Withdrawals');
$withdrawalHeaders = array('Amount', 'Approve Date');
$withdrawalWidths = array(95, 95);
$pdf->TableHeader($withdrawalHeaders, $withdrawalWidths);

while ($withdrawal = $withdrawalsResult->fetch_assoc()) {
    $pdf->TableRow(array(
        number_format($withdrawal['amount'], 2),
        $withdrawal['ApproveDate']
    ), $withdrawalWidths);
}

$pdf->Output();
?>