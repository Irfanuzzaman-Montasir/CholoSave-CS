-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Jan 26, 2025 at 02:43 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `cholosave_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `contact_us`
--

CREATE TABLE `contact_us` (
  `id` int(11) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `status` enum('pending','done') NOT NULL DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `contact_us`
--

INSERT INTO `contact_us` (`id`, `name`, `email`, `description`, `status`, `created_at`) VALUES
(1, 'CCLLL', 'a@gm.com', 'Smith is a seasoned investment strategist with over 12 years of experience in portfolio management and financial planning. He specializes in guiding clients toward achieving long-term wealth through diversified investments.', 'pending', '2025-01-17 15:38:16'),
(2, 'CCLLL', 'a@gm.com', 'fasewserfqawdaefawsefaefqawedfqawefae', 'done', '2025-01-17 15:39:30'),
(3, 'Rajjak', 'razzak@kosto.com', 'Kosto', 'pending', '2025-01-17 20:38:47'),
(4, 'Montasir', 'a@gmail.com', 'Tehgabd', 'pending', '2025-01-25 06:29:20');

-- --------------------------------------------------------

--
-- Table structure for table `expert_team`
--

CREATE TABLE `expert_team` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `phone` varchar(15) NOT NULL,
  `expertise` varchar(255) NOT NULL,
  `bio` text NOT NULL,
  `image` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `expert_team`
--

INSERT INTO `expert_team` (`id`, `name`, `email`, `phone`, `expertise`, `bio`, `image`, `created_at`) VALUES
(5, 'Saul \"Save It All\" Goodman', 'bettercall@saul.com', '0183746384', 'Legal Investment Advisor', 'When it comes to finding loopholes in contracts or turning pennies into pounds, Saul\'s your guy! A self-proclaimed \"lawyer for the people,\" Saul specializes in creative investment strategies that might make you question legality (but hey, it’s technically legal). His motto? \"Save it all, then spend it all on me.', 'expert_5.png', '2025-01-19 18:25:33'),
(6, 'Pablo \"Profit King\" Cashbar', 'pablo@escober.com', '99018233491', 'Risk and High-Yield Advisor', ' Pablo brings a risky yet rewarding touch to your investment plans. With experience in \"alternative investments,\" his strategies promise sky-high returns—but only if you’re ready to dare. Just don’t ask where the money comes from. Pablo’s advice? \"Invest smart, or else...', 'expert_6.png', '2025-01-19 18:26:36'),
(7, 'Tony \"Tax Whisperer\" Starks', 'tony@stark.com', '2345743256', 'Tax Optimization Specialist', 'A genius playboy philanthropist turned tax guru. Tony claims he can \"outsmart the IRS in his sleep.\" Whether it’s deductions, credits, or offshore accounts, Tony\'s plans will save you so much you’ll feel like you’ve hacked the system. Favorite line: \"Keep your taxes as low as my ego is high.', 'expert_7.png', '2025-01-19 18:29:19'),
(8, 'Jordan \"The Wolf\" Belfake', 'jordan@belfake.com', '246785432', 'Stock Market Shark', 'Jordan has seen it all—from meteoric rises to catastrophic crashes. Known for his aggressive trading style, his philosophy is simple: \"Buy low, sell high, and party harder.\" He claims his investment app WolfWatch can track the market trends faster than a caffeine rush.', 'expert_8.png', '2025-01-19 18:38:08'),
(9, 'Vito \"The Don\" Investioni', 'vito@don.com', '2357812367', 'Long-Term Investment Strategist', 'Vito doesn’t just save money—he makes money. Known for his love of power suits and his \"make an offer you can’t refuse\" investment plans, he believes in the art of slow and steady growth. His tip? \"Patience grows the money tree.', 'expert_9.png', '2025-01-19 18:41:48');

-- --------------------------------------------------------

--
-- Table structure for table `group_membership`
--

CREATE TABLE `group_membership` (
  `membership_id` int(11) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `status` enum('pending','approved','declined') DEFAULT 'pending',
  `is_admin` tinyint(1) DEFAULT 0,
  `leave_request` enum('pending','approved','declined','no') DEFAULT 'no',
  `join_date` date DEFAULT NULL,
  `join_request_date` date DEFAULT NULL,
  `time_period_remaining` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `group_membership`
--

INSERT INTO `group_membership` (`membership_id`, `group_id`, `user_id`, `status`, `is_admin`, `leave_request`, `join_date`, `join_request_date`, `time_period_remaining`) VALUES
(1, 1, 1, 'approved', 1, 'no', '2025-01-12', NULL, 2),
(2, 2, 7, 'approved', 1, 'no', '2025-01-12', NULL, NULL),
(3, 1, 7, 'approved', 0, 'pending', '2025-01-12', '2025-01-12', 6),
(4, 3, 8, 'pending', 1, 'no', NULL, '2025-01-13', NULL),
(5, 1, 9, 'approved', 0, 'no', '2025-01-15', '2025-01-13', 12),
(6, 1, 8, 'approved', 0, 'no', '2025-01-16', '2025-01-13', 12),
(7, 1, 10, 'declined', 0, 'approved', NULL, NULL, NULL),
(8, 2, 10, 'approved', 0, 'no', '2025-01-24', '2025-01-13', 52),
(9, 3, 10, 'pending', 0, 'no', NULL, '2025-01-13', NULL),
(10, 2, 1, 'pending', 0, 'no', NULL, '2025-01-14', NULL),
(15, 4, 1, 'approved', 1, 'no', '2025-01-17', NULL, 11),
(30, 19, 1, 'approved', 1, 'no', '2025-01-26', NULL, 12);

-- --------------------------------------------------------

--
-- Table structure for table `investments`
--

CREATE TABLE `investments` (
  `investment_id` int(11) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `investment_type` varchar(255) DEFAULT NULL,
  `ex_profit` double DEFAULT NULL,
  `ex_return_date` date DEFAULT NULL,
  `status` enum('pending','completed') NOT NULL DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `investments`
--

INSERT INTO `investments` (`investment_id`, `group_id`, `amount`, `investment_type`, `ex_profit`, `ex_return_date`, `status`, `created_at`) VALUES
(1, 1, 100.00, 'House', 150, '0000-00-00', 'completed', '2025-01-12 22:30:37'),
(3, 1, 335.00, 'Test', 1313, '2025-01-20', 'pending', '2025-01-12 22:35:58');

-- --------------------------------------------------------

--
-- Table structure for table `investment_returns`
--

CREATE TABLE `investment_returns` (
  `return_id` int(11) NOT NULL,
  `investment_id` int(11) DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `return_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `description` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `investment_returns`
--

INSERT INTO `investment_returns` (`return_id`, `investment_id`, `amount`, `return_date`, `description`) VALUES
(3, 1, 670.00, '2025-01-12 22:50:51', 'ABCD');

-- --------------------------------------------------------

--
-- Table structure for table `leaderboard`
--

CREATE TABLE `leaderboard` (
  `id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  `points` decimal(10,2) DEFAULT 0.00,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `leaderboard`
--

INSERT INTO `leaderboard` (`id`, `group_id`, `points`, `updated_at`) VALUES
(1, 1, 85.00, '2025-01-17 17:32:04'),
(2, 2, 75.00, '2025-01-24 15:50:25'),
(3, 3, 60.00, '2025-01-15 10:30:18'),
(4, 4, 55.00, '2025-01-17 16:57:27'),
(18, 19, 55.00, '2025-01-25 22:11:05');

-- --------------------------------------------------------

--
-- Table structure for table `loan_repayments`
--

CREATE TABLE `loan_repayments` (
  `repayment_id` int(11) NOT NULL,
  `loan_id` int(11) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `payment_date` datetime DEFAULT current_timestamp(),
  `payment_method` varchar(50) DEFAULT NULL,
  `transaction_reference` varchar(100) DEFAULT NULL,
  `status` enum('pending','completed','failed') DEFAULT 'pending'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `loan_request`
--

CREATE TABLE `loan_request` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `reason` text DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `status` enum('pending','approved','declined','repaid') DEFAULT 'pending',
  `return_time` date DEFAULT NULL,
  `approve_date` date DEFAULT NULL,
  `request_time` timestamp NOT NULL DEFAULT current_timestamp(),
  `repayment_date` datetime DEFAULT NULL,
  `repayment_amount` decimal(10,2) DEFAULT 0.00,
  `payment_method` enum('bkash','Rocket','Nagad') DEFAULT NULL,
  `transaction_id` varchar(255) DEFAULT NULL,
  `payment_time` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `loan_request`
--

INSERT INTO `loan_request` (`id`, `user_id`, `group_id`, `reason`, `amount`, `status`, `return_time`, `approve_date`, `request_time`, `repayment_date`, `repayment_amount`, `payment_method`, `transaction_id`, `payment_time`) VALUES
(1, 7, 1, 'Testing ABC', 100.00, 'repaid', '2025-01-15', '2025-01-12', '2025-01-12 17:14:43', '2025-01-13 00:00:00', 100.00, 'bkash', 'CHS93c56AVE', '2025-01-13 01:16:16'),
(2, 7, 1, 'gfaeuiabf', 500.00, 'repaid', '2025-01-30', '2025-01-13', '2025-01-12 19:16:49', '2025-01-13 00:00:00', 500.00, 'Nagad', 'CHS73bc5AVE', '2025-01-13 21:55:11'),
(3, 10, 1, 'Need Urgent', 100.00, 'approved', '2025-01-20', '2025-01-13', '2025-01-12 21:03:32', NULL, 0.00, NULL, NULL, NULL),
(4, 1, 1, 'qwefwe', 200.00, 'repaid', '2025-01-21', '2025-01-13', '2025-01-12 21:26:24', '2025-01-13 00:00:00', 200.00, 'Rocket', 'CHS6D052AVE', '2025-01-13 22:09:14'),
(5, 1, 1, 'vsrsrsrvs', 1000.00, 'repaid', '2025-01-30', '2025-01-15', '2025-01-15 08:41:48', '2025-01-16 00:00:00', 1000.00, 'Rocket', 'CHSB8659AVE', '2025-01-16 22:03:05'),
(6, 7, 1, 'aaaca', 500.00, 'repaid', '2025-01-17', '2025-01-15', '2025-01-15 14:59:10', '2025-01-16 00:00:00', 500.00, 'Rocket', 'CHS88cf8AVE', '2025-01-16 13:43:50'),
(7, 9, 1, 'Abjsbcak', 500.00, 'approved', '2025-01-17', '2025-01-16', '2025-01-15 21:23:35', NULL, 0.00, NULL, NULL, NULL),
(8, 7, 1, 'grrr', 1500.00, 'repaid', '2025-01-24', '2025-01-16', '2025-01-16 07:44:07', '2025-01-16 00:00:00', 1500.00, 'bkash', 'CHS3Be28AVE', '2025-01-16 14:45:59'),
(16, 7, 1, 'Tewst poll', 335.00, 'repaid', '2025-01-22', '2025-01-17', '2025-01-16 17:39:18', '2025-01-17 00:00:00', 335.00, 'Nagad', 'CHS1Ef36AVE', '2025-01-17 22:22:49'),
(19, 1, 1, 'vsdvsadv', 500.00, 'repaid', '2025-01-23', '2025-01-17', '2025-01-17 09:34:06', '2025-01-17 00:00:00', 500.00, 'Rocket', 'CHSD2648AVE', '2025-01-17 19:15:41'),
(20, 1, 4, 'Testing', 500.00, 'repaid', '2025-01-28', '2025-01-26', '2025-01-25 21:47:58', '2025-01-26 00:00:00', 500.00, 'Nagad', 'CHS52d23AVE', '2025-01-26 14:01:22'),
(21, 1, 1, 'Nothidindg', 1000.00, 'approved', '2025-01-28', '2025-01-26', '2025-01-26 11:24:53', NULL, 0.00, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `messages`
--

INSERT INTO `messages` (`id`, `group_id`, `user_id`, `message`, `created_at`) VALUES
(1, 1, 1, 'hey', '2025-01-17 17:21:49'),
(2, 1, 7, 'hello', '2025-01-17 17:21:55'),
(3, 1, 1, 'hi nahin', '2025-01-17 17:48:19'),
(4, 1, 7, 'hi irfan', '2025-01-17 17:48:25'),
(5, 1, 1, 'Hey There', '2025-01-20 08:28:29'),
(6, 1, 7, 'Testing 1 2 3', '2025-01-20 08:28:36'),
(7, 1, 9, 'I am Back guys', '2025-01-20 08:30:50'),
(8, 1, 7, 'dbdgfb', '2025-01-20 08:38:29');

-- --------------------------------------------------------

--
-- Table structure for table `my_group`
--

CREATE TABLE `my_group` (
  `group_id` int(11) NOT NULL,
  `group_name` varchar(255) DEFAULT NULL,
  `members` int(11) NOT NULL,
  `group_admin_id` int(11) DEFAULT NULL,
  `dps_type` enum('weekly','monthly') DEFAULT NULL,
  `time_period` int(11) DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `goal_amount` int(11) DEFAULT NULL,
  `warning_time` int(11) DEFAULT NULL,
  `emergency_fund` decimal(8,2) DEFAULT NULL,
  `bKash` varchar(255) DEFAULT NULL,
  `Rocket` varchar(255) DEFAULT NULL,
  `Nagad` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `description` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `my_group`
--

INSERT INTO `my_group` (`group_id`, `group_name`, `members`, `group_admin_id`, `dps_type`, `time_period`, `amount`, `start_date`, `goal_amount`, `warning_time`, `emergency_fund`, `bKash`, `Rocket`, `Nagad`, `created_at`, `description`) VALUES
(1, 'Mig 29', 10, 1, 'monthly', 12, 500.00, '2024-12-27', 50000, 2, 3500.00, '01634132218', '01634132218', '0157589393', '2025-01-12 17:03:23', 'This a group where you can save money with transparent'),
(2, 'Irfan&#39;s Group', 10, 7, 'weekly', 52, 200.00, '2025-01-25', 80000, 3, 8000.00, '1648248681', '01648248681', '01648248681', '2025-01-12 17:12:56', 'Testing Purpose'),
(3, 'Test Time', 10, 8, 'monthly', 24, 700.00, '2025-01-20', 70000, 3, 7000.00, '1648248681', '01648248681', '01648248681', '2025-01-12 19:50:37', 'ofjwfnwnwsrowsrkmgkwerpm'),
(4, 'Leaderboard testing', 10, 1, 'monthly', 11, 335.00, '2025-01-23', 50000, 12, 5000.00, '1634132218', '01634132218', '01634132218', '2025-01-17 16:57:27', 'iasdnaemc'),
(19, 'Final Boss', 12, 1, 'weekly', 12, 100.00, '2025-01-29', 500000, NULL, 5000.00, '1634132218', '01634132218', '01634132218', '2025-01-25 22:11:05', 'faigaefeirhfejfrhfhewdefnrwjghf4wrfp4rftou');

-- --------------------------------------------------------

--
-- Table structure for table `my_savings`
--

CREATE TABLE `my_savings` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `total_amount` decimal(10,2) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `my_savings`
--

INSERT INTO `my_savings` (`id`, `user_id`, `group_id`, `total_amount`) VALUES
(1, 8, 1, 4900.00);

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `notification_id` int(11) NOT NULL,
  `target_user_id` int(11) DEFAULT NULL,
  `target_group_id` int(11) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `status` enum('unread','read') DEFAULT 'unread',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `type` enum('loan_approval','withdrawal','join_request','payment_reminder','group_loan_request','leave_request','group_withdraw_request','admin_promotion','close_savings') NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `notifications`
--

INSERT INTO `notifications` (`notification_id`, `target_user_id`, `target_group_id`, `title`, `message`, `status`, `created_at`, `type`) VALUES
(3, 9, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'read', '2025-01-15 20:59:35', 'join_request'),
(4, NULL, 1, 'New Member Joined', 'Irfanuzzaman Montasir joined the group.', 'unread', '2025-01-15 20:59:35', 'join_request'),
(9, NULL, 1, 'New Loan Approved', 'A loan request for BDT 1500.00 has been approved.', 'unread', '2025-01-16 07:44:22', 'loan_approval'),
(10, 8, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 07:49:47', 'join_request'),
(11, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 07:49:47', 'join_request'),
(17, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $100.00 by user \'Irfan\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 08:02:37', 'withdrawal'),
(18, 8, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 08:20:36', 'join_request'),
(19, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 08:20:36', 'join_request'),
(21, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $100.00 by user \'Irfan\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 08:27:30', 'withdrawal'),
(23, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $100.00 by user \'Irfan\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 08:29:58', 'withdrawal'),
(25, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $100.00 by user \'Irfan\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 08:35:49', 'withdrawal'),
(27, NULL, 1, 'New Loan Approved', 'A loan request for BDT 1500.00 has been approved.', 'unread', '2025-01-16 08:45:48', 'loan_approval'),
(30, 1, 1, ' Group Admin Promotion', 'You have been promoted to admin of the group.', 'unread', '2025-01-16 15:23:24', 'admin_promotion'),
(32, 1, 1, ' Group Admin Promotion', 'You have been promoted to admin of the group.', 'unread', '2025-01-16 18:49:08', 'admin_promotion'),
(34, NULL, 1, 'New Loan Approved', 'A loan request for BDT 335.00 has been approved.', 'unread', '2025-01-16 18:50:39', 'loan_approval'),
(35, 13, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 19:50:59', 'join_request'),
(36, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 19:50:59', 'join_request'),
(37, 13, NULL, 'Loan Request Approved', 'Your loan request for BDT 500.00 in group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-16 19:53:59', 'loan_approval'),
(38, NULL, 1, 'New Loan Approved', 'A loan request for BDT 500.00 has been approved.', 'unread', '2025-01-16 19:53:59', 'loan_approval'),
(39, 13, NULL, 'Withdrawal Approved', 'Hi Leave Testing, your withdrawal request of $500.00 for the group \'CHOLOSAVE\' has been approved. Please check your payment method for updates.', 'unread', '2025-01-16 19:55:46', 'withdrawal'),
(40, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $500.00 by user \'Leave Testing\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 19:55:46', 'withdrawal'),
(41, 13, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 20:04:52', 'join_request'),
(42, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 20:04:52', 'join_request'),
(43, 13, NULL, 'Withdrawal Approved', 'Hi Leave Testing, your withdrawal request of $500.00 for the group \'CHOLOSAVE\' has been approved. Please check your payment method for updates.', 'unread', '2025-01-16 20:10:02', 'withdrawal'),
(44, NULL, 1, 'Withdrawal Processed', 'A withdrawal of $500.00 by user \'Leave Testing\' has been processed for the group \'CHOLOSAVE\'.', 'unread', '2025-01-16 20:10:02', 'withdrawal'),
(45, 13, NULL, 'Leave Request Approved', 'Your request to leave the group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-16 20:10:23', 'leave_request'),
(46, NULL, 1, 'Member Left Group', 'Member \'Leave Testing\' has left the group.', 'unread', '2025-01-16 20:10:23', 'leave_request'),
(47, 13, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 20:21:13', 'join_request'),
(48, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 20:21:13', 'join_request'),
(49, 13, NULL, 'Leave Request Approved', 'Your request to leave the group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-16 20:21:42', 'leave_request'),
(50, NULL, 1, 'Member Left Group', 'Member \'Leave Testing\' has left the group.', 'unread', '2025-01-16 20:21:42', 'leave_request'),
(51, 13, NULL, 'Leave Request Approved', 'Your request to leave the group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-16 20:21:46', 'leave_request'),
(52, NULL, 1, 'Member Left Group', 'Member \'Leave Testing\' has left the group.', 'unread', '2025-01-16 20:21:46', 'leave_request'),
(53, 13, NULL, 'Join Request Approved', 'Your request to join the group \'CHOLOSAVE\' has been approved. Welcome to the group!', 'unread', '2025-01-16 20:22:21', 'join_request'),
(54, NULL, 1, 'New Member Joined', 'A new member has joined your group \'CHOLOSAVE\'.', 'unread', '2025-01-16 20:22:21', 'join_request'),
(55, 13, NULL, 'Leave Request Approved', 'Your request to leave the group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-16 20:24:11', 'leave_request'),
(56, NULL, 1, 'Member Left Group', 'Member \'Leave Testing\' has left the group.', 'unread', '2025-01-16 20:24:11', 'leave_request'),
(57, 1, NULL, 'Loan Request Approved', 'Your loan request for BDT 500.00 in group \'CHOLOSAVE\' has been approved.', 'unread', '2025-01-17 13:15:16', 'loan_approval'),
(58, NULL, 1, 'New Loan Approved', 'A loan request for BDT 500.00 has been approved.', 'unread', '2025-01-17 13:15:16', 'loan_approval'),
(60, NULL, 1, 'Group Admin Change', 'A new admin has been assigned to the group.', 'unread', '2025-01-23 12:19:33', 'admin_promotion'),
(61, 1, NULL, 'Group Admin Promotion', 'You have been promoted to admin of the group \'CHOLOSAVE\'.', 'unread', '2025-01-23 12:21:56', 'admin_promotion'),
(62, NULL, 1, 'Group Admin Change', 'A new admin has been assigned to the group.', 'unread', '2025-01-23 12:21:56', 'admin_promotion'),
(64, NULL, 1, 'Group Admin Change', 'A new admin has been assigned to the group.', 'unread', '2025-01-23 22:08:33', 'admin_promotion'),
(65, 1, NULL, 'Group Admin Promotion', 'You have been promoted to admin of the group \'CHOLOSAVE\'.', 'unread', '2025-01-23 22:09:28', 'admin_promotion'),
(66, NULL, 1, 'Group Admin Change', 'A new admin has been assigned to the group.', 'unread', '2025-01-23 22:09:28', 'admin_promotion'),
(67, 10, NULL, 'Join Request Approved', 'Your request to join the group \'Irfan&#39;s Group\' has been approved. Welcome to the group!', 'unread', '2025-01-24 15:50:25', 'join_request'),
(68, NULL, 2, 'New Member Joined', 'A new member has joined your group \'Irfan&#39;s Group\'.', 'unread', '2025-01-24 15:50:25', 'join_request'),
(70, 1, NULL, 'Group Closing', 'Your Test has been closed.', 'unread', '2025-01-25 19:37:17', 'close_savings'),
(71, 1, NULL, 'Group Closing', 'Your savings groupTest has been closed.', 'unread', '2025-01-25 19:48:14', 'close_savings'),
(72, 1, NULL, 'Group Closing', 'Your savings groupTest has been closed.', 'unread', '2025-01-25 19:49:18', 'close_savings'),
(73, 1, NULL, 'Group Closing', 'Your savings groupTest has been closed.', 'unread', '2025-01-25 19:51:37', 'close_savings'),
(80, 1, NULL, 'Loan Request Approved', 'Your loan request for BDT 500.00 in group \'Leaderboard testing\' has been approved.', 'unread', '2025-01-25 21:48:11', 'loan_approval'),
(81, NULL, 4, 'New Loan Approved', 'A loan request for BDT 500.00 has been approved.', 'unread', '2025-01-25 21:48:11', 'loan_approval'),
(82, 1, NULL, 'Group Closing', 'Your savings group  has been closed.', 'unread', '2025-01-25 21:59:44', 'close_savings'),
(83, 1, NULL, 'Group Closing', 'Your savings group  has been closed.', 'unread', '2025-01-25 22:05:18', 'close_savings'),
(84, 1, NULL, 'Group Closing', 'Your savings group Test has been closed.', 'unread', '2025-01-25 22:09:53', 'close_savings'),
(85, 1, NULL, 'Loan Request Approved', 'Your loan request for BDT 1000.00 in group \'Mig 29\' has been approved.', 'unread', '2025-01-26 11:25:01', 'loan_approval'),
(86, NULL, 1, 'New Loan Approved', 'A loan request for BDT 1000.00 has been approved.', 'unread', '2025-01-26 11:25:01', 'loan_approval');

-- --------------------------------------------------------

--
-- Table structure for table `password_reset_tokens`
--

CREATE TABLE `password_reset_tokens` (
  `email` varchar(255) NOT NULL,
  `otp_hash` varchar(255) NOT NULL,
  `expiry` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `password_reset_tokens`
--

INSERT INTO `password_reset_tokens` (`email`, `otp_hash`, `expiry`) VALUES
('david657987@gmail.com', '$2y$10$FxALwFkaVSEon8QzjM1OJ.i/29P.MT2yZZexexqnMB3HUT3/Tqooy', '2025-01-25 09:00:02');

-- --------------------------------------------------------

--
-- Table structure for table `polls`
--

CREATE TABLE `polls` (
  `poll_id` int(11) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  `poll_question` text DEFAULT NULL,
  `status` enum('active','closed') DEFAULT 'active',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `polls`
--

INSERT INTO `polls` (`poll_id`, `group_id`, `poll_question`, `status`, `created_at`) VALUES
(2, 1, 'Irfan has requested a loan of BDT 500. Do you approve?', 'active', '2025-01-12 17:14:43'),
(3, 1, 'Irfanuzzaman Montasir wants to join the group. Do you approve?', 'active', '2025-01-12 20:47:48'),
(4, 1, 'Drake wants to join the group. Do you approve?', 'active', '2025-01-12 20:48:08'),
(5, 1, 'Drake X wants to join the group. Do you approve?', 'active', '2025-01-12 20:48:24'),
(6, 2, 'Drake X wants to join the group. Do you approve?', 'active', '2025-01-12 20:48:25'),
(15, 2, 'Montasir wants to join the group. Do you approve?', 'active', '2025-01-13 19:33:40'),
(16, 1, 'Irfan has requested a loan of BDT 335. Do you approve?', 'active', '2025-01-16 17:39:18'),
(17, 1, 'Leave Testing wants to join the group. Do you approve?', 'active', '2025-01-16 19:50:42'),
(24, 4, 'Montasir (Admin) has requested a loan of BDT 500. Do you approve?', 'active', '2025-01-25 21:47:58'),
(25, 1, 'Montasir (Admin) has requested a loan of BDT 1000. Do you approve?', 'active', '2025-01-26 11:24:53');

-- --------------------------------------------------------

--
-- Table structure for table `polls_vote`
--

CREATE TABLE `polls_vote` (
  `vote_id` int(11) NOT NULL,
  `poll_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `vote_option` enum('yes','no') NOT NULL,
  `voted_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `polls_vote`
--

INSERT INTO `polls_vote` (`vote_id`, `poll_id`, `user_id`, `vote_option`, `voted_at`) VALUES
(2, 4, 1, 'yes', '2025-01-12 21:15:19'),
(3, 2, 1, 'yes', '2025-01-13 11:38:41'),
(4, 3, 1, 'no', '2025-01-16 14:15:28'),
(5, 17, 1, 'yes', '2025-01-16 19:50:53'),
(6, 2, 7, 'no', '2025-01-24 14:56:49');

-- --------------------------------------------------------

--
-- Table structure for table `questions`
--

CREATE TABLE `questions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `title` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `views` int(11) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `questions`
--

INSERT INTO `questions` (`id`, `user_id`, `title`, `content`, `created_at`, `updated_at`, `views`) VALUES
(1, 1, 'Investments', 'Hi, I am Montasir. I want to get some ideas about investment.', '2025-01-15 11:05:50', '2025-01-25 20:37:58', 24),
(3, 7, 'ABC', 'fseiseseaefelpjwejokerkpefkpwsme', '2025-01-15 11:26:42', '2025-01-25 20:27:32', 15),
(4, 1, 'About Invest', 'Hi , this is nahin . I want to join group', '2025-01-15 12:35:08', '2025-01-25 20:27:34', 55),
(6, 1, 'About Investment', 'Hey, Can I get Some info on how much should I invest on my 1200 savings?', '2025-01-25 20:18:57', '2025-01-26 08:45:38', 26);

-- --------------------------------------------------------

--
-- Table structure for table `reactions`
--

CREATE TABLE `reactions` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `question_id` int(11) DEFAULT NULL,
  `reply_id` int(11) DEFAULT NULL,
  `reaction_type` enum('upvote','downvote') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `reactions`
--

INSERT INTO `reactions` (`id`, `user_id`, `question_id`, `reply_id`, `reaction_type`, `created_at`) VALUES
(11, 7, NULL, 2, 'upvote', '2025-01-15 11:20:39'),
(12, 7, 1, NULL, 'upvote', '2025-01-15 11:23:00'),
(23, 1, NULL, 5, 'upvote', '2025-01-15 12:36:56'),
(25, 7, 4, NULL, 'upvote', '2025-01-15 12:37:12'),
(37, 7, NULL, 4, 'upvote', '2025-01-15 12:37:54'),
(40, 1, 4, NULL, 'upvote', '2025-01-25 05:42:34'),
(43, 1, NULL, 4, 'upvote', '2025-01-25 05:42:45'),
(46, 1, 3, NULL, 'upvote', '2025-01-25 06:32:37');

-- --------------------------------------------------------

--
-- Table structure for table `replies`
--

CREATE TABLE `replies` (
  `id` int(11) NOT NULL,
  `question_id` int(11) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `content` text NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `replies`
--

INSERT INTO `replies` (`id`, `question_id`, `user_id`, `content`, `created_at`, `updated_at`) VALUES
(2, 1, 7, 'ok ok', '2025-01-15 11:13:36', '2025-01-15 11:13:36'),
(3, 1, 1, 'no no\r\n', '2025-01-15 11:45:31', '2025-01-15 11:45:31'),
(4, 4, 7, 'No, I can\'t help', '2025-01-15 12:35:58', '2025-01-15 12:35:58'),
(5, 4, 1, 'ok thanks', '2025-01-15 12:36:36', '2025-01-15 12:36:36'),
(6, 4, 1, 'hghghgh', '2025-01-25 06:03:31', '2025-01-25 06:03:31'),
(7, 6, 1, 'Anyone?', '2025-01-25 20:20:50', '2025-01-25 20:20:50');

-- --------------------------------------------------------

--
-- Table structure for table `savings`
--

CREATE TABLE `savings` (
  `savings_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `savings`
--

INSERT INTO `savings` (`savings_id`, `user_id`, `group_id`, `amount`, `created_at`) VALUES
(1, 7, 1, 500.00, '2024-12-10 17:15:09'),
(2, 10, 1, 500.00, '2024-12-17 20:56:49'),
(3, 1, 1, 500.00, '2025-01-12 22:04:04'),
(4, 1, 1, 500.00, '2025-01-12 22:07:48'),
(5, 1, 1, 500.00, '2024-12-16 05:27:48'),
(6, 1, 1, 500.00, '2025-01-13 12:40:30'),
(7, 1, 1, 500.00, '2024-11-18 12:44:22'),
(8, 1, 1, 500.00, '2025-01-13 12:52:54'),
(9, 1, 1, 500.00, '2024-11-11 15:46:45'),
(10, 1, 1, 500.00, '2024-11-19 17:28:43'),
(11, 1, 1, 500.00, '2025-01-13 17:29:23'),
(12, 1, 1, 500.00, '2024-10-23 17:30:55'),
(16, 7, 1, 500.00, '2025-01-13 17:52:08'),
(17, 7, 1, 500.00, '2025-01-13 17:53:12'),
(18, 7, 1, 500.00, '2025-01-13 17:53:55'),
(19, 7, 1, 500.00, '2025-01-15 14:49:54'),
(22, 7, 1, 500.00, '2025-01-17 17:11:37'),
(23, 7, 1, 500.00, '2025-01-17 17:32:04');

-- --------------------------------------------------------

--
-- Table structure for table `transaction_info`
--

CREATE TABLE `transaction_info` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  `amount` decimal(8,2) NOT NULL,
  `transaction_id` varchar(255) NOT NULL,
  `payment_method` enum('bKash','Rocket','Nagad') NOT NULL,
  `payment_time` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `transaction_info`
--

INSERT INTO `transaction_info` (`id`, `user_id`, `group_id`, `amount`, `transaction_id`, `payment_method`, `payment_time`) VALUES
(1, 7, 1, 500.00, 'CHS8D486AVE', 'bKash', '2025-01-12 17:15:09'),
(2, 10, 1, 500.00, 'CHS47928AVE', 'bKash', '2025-01-12 20:56:49'),
(3, 1, 1, 500.00, 'CHSC0205AVE', 'Nagad', '2025-01-12 22:04:04'),
(4, 1, 1, 500.00, 'CHS24987AVE', 'Rocket', '2025-01-12 22:07:48'),
(5, 1, 1, 500.00, 'CHS5A843AVE', 'bKash', '2025-01-13 05:27:48'),
(6, 1, 1, 500.00, 'CHS10d57AVE', 'bKash', '2025-01-13 12:40:30'),
(7, 1, 1, 500.00, 'CHS1D951AVE', 'Rocket', '2025-01-13 12:44:22'),
(8, 1, 1, 500.00, 'CHSC3526AVE', 'Nagad', '2025-01-13 12:52:54'),
(9, 1, 1, 500.00, 'CHSFC455AVE', 'bKash', '2025-01-13 15:46:45'),
(10, 1, 1, 500.00, 'CHSAA7f4AVE', 'bKash', '2025-01-13 17:28:43'),
(11, 1, 1, 500.00, 'CHSDF748AVE', 'Rocket', '2025-01-13 17:29:23'),
(12, 1, 1, 500.00, 'CHS7E6f9AVE', 'Nagad', '2025-01-13 17:30:55'),
(16, 7, 1, 500.00, 'CHS9F455AVE', 'Nagad', '2025-01-13 17:52:08'),
(17, 7, 1, 500.00, 'CHS58c37AVE', 'Rocket', '2025-01-13 17:53:12'),
(18, 7, 1, 500.00, 'CHSF6671AVE', 'Nagad', '2025-01-13 17:53:55'),
(19, 7, 1, 500.00, 'CHS1C377AVE', 'Nagad', '2025-01-15 14:49:54'),
(22, 7, 1, 500.00, 'CHS07501AVE', 'bKash', '2025-01-17 17:11:37'),
(23, 7, 1, 500.00, 'CHS07879AVE', 'bKash', '2025-01-17 17:32:04');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `role` enum('user','group_admin','admin') DEFAULT 'user',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `profile_picture` varchar(255) NOT NULL,
  `otp` varchar(6) DEFAULT NULL,
  `otp_expiry` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `name`, `email`, `phone_number`, `password`, `role`, `created_at`, `profile_picture`, `otp`, `otp_expiry`) VALUES
(1, 'Montasir', 'a@gmail.com', '01634132218', '$2y$10$8yoTBuHB33.6UuT7rkNJZOxesqYdfXclb7wV/rWV51UerIJUI9w7i', 'user', '2025-01-12 15:49:27', 'user_1.png', NULL, NULL),
(7, 'Irfan', 'b@gmail.com', '01634132218', '$2y$10$Cdm9VGGGKKT7PGuFIpB.n.9Kf/HI29.XCOCz./qSMKTf94lcbf1km', 'user', '2025-01-12 17:06:19', 'user_7.jpeg', NULL, NULL),
(8, 'Drake', 'd@gmail.com', '0192378487', '$2y$10$wUqlf.tkSJtptXN22eun6OtkMdIJLC4u0/zad0yR/xss7lzYtz1t.', 'user', '2025-01-12 19:49:36', '', NULL, NULL),
(9, 'Irfanuzzaman Montasir', 'c@gmail.com', '01634132218', '$2y$10$92UlcshqFr5UcGAHPk/uiuGxwCkwXIgN7/AYrO/y9X9ft9GuGSU8W', 'user', '2025-01-12 20:42:43', '', NULL, NULL),
(10, 'Drake X', 'e@gmail.com', '0192378487', '$2y$10$.VYwQsI9qlBP42CFIYQoIuTLe44HSUa6B5k9DaaKPJc6LlEOtShdC', 'user', '2025-01-12 20:46:42', '', NULL, NULL),
(11, 'Fat', 'f@gmail.com', '0192378487', '$2y$10$x9HaOkw.HWVmUGIRiAYX.OijWRq2sPyC4cAd3PxbcVZRsWDXZVOL2', 'user', '2025-01-12 20:47:01', '', NULL, NULL),
(12, 'George', 'g@gmail.com', '01634132218', '$2y$10$XtlAbodK4bSuuKLRK64i0eWWUHjNt3x2ridb53ULcuyoEG4QmUEne', 'user', '2025-01-12 20:47:26', '', NULL, NULL),
(13, 'Leave Testing', 'leave@gmail.com', '01634132218', '$2y$10$tQP587rN1AIJBX4a5wv.nOas34Y6ybtqwVQeV87JTmK4mStrhztUi', 'user', '2025-01-16 19:44:18', '', NULL, NULL),
(14, 'Admin', 'admin@gmail.com', '0183746384', '$2y$10$idNRxZjI6Rh0kmZIUrNh5e4dLP83YJMz/JSZfoFubPhxEnKPVwyT2', 'admin', '2025-01-17 14:04:50', '', NULL, NULL),
(15, 'Profile Test', 'p@gmail.com', '01634132218', '$2y$10$d9fwxmzaRGNXLtqHP9JLzOj9OXEnyJaPM21wBUHHlj3QiwubX2wc.', 'user', '2025-01-19 13:27:24', '', NULL, NULL),
(16, 'David', 'david657987@gmail.com', '01634132218', '$2y$10$2D1Ep9ZeDuPz0hYu4hSHN.tU6KltlrKbXe3Z2y1.VrHIGalGWhCD2', 'user', '2025-01-25 07:44:57', '', '322033', '2025-01-26 17:59:38');

-- --------------------------------------------------------

--
-- Table structure for table `withdrawal`
--

CREATE TABLE `withdrawal` (
  `withdrawal_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `amount` decimal(8,2) DEFAULT NULL,
  `payment_number` varchar(255) NOT NULL,
  `payment_method` varchar(255) NOT NULL,
  `status` enum('pending','approved','declined') DEFAULT 'pending',
  `request_date` timestamp NOT NULL DEFAULT current_timestamp(),
  `approve_date` date DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `withdrawal`
--

INSERT INTO `withdrawal` (`withdrawal_id`, `user_id`, `group_id`, `amount`, `payment_number`, `payment_method`, `status`, `request_date`, `approve_date`) VALUES
(1, 7, 1, 500.00, '01634132217', 'Bkash', 'approved', '2025-01-13 06:35:35', NULL),
(2, 1, 1, 200.00, '01601245256', 'Nagad', 'approved', '2025-01-13 06:40:03', '2025-01-16'),
(3, 7, 1, 100.00, '01634132217', 'Nagad', 'approved', '2025-01-13 15:56:49', '2025-01-16'),
(6, 1, 1, 335.00, 'adada', 'Bkash', 'pending', '2025-01-17 12:40:07', NULL);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `contact_us`
--
ALTER TABLE `contact_us`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `expert_team`
--
ALTER TABLE `expert_team`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- Indexes for table `group_membership`
--
ALTER TABLE `group_membership`
  ADD PRIMARY KEY (`membership_id`),
  ADD KEY `group_id` (`group_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `investments`
--
ALTER TABLE `investments`
  ADD PRIMARY KEY (`investment_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `investment_returns`
--
ALTER TABLE `investment_returns`
  ADD PRIMARY KEY (`return_id`),
  ADD KEY `investment_id` (`investment_id`);

--
-- Indexes for table `leaderboard`
--
ALTER TABLE `leaderboard`
  ADD PRIMARY KEY (`id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `loan_repayments`
--
ALTER TABLE `loan_repayments`
  ADD PRIMARY KEY (`repayment_id`),
  ADD KEY `loan_id` (`loan_id`);

--
-- Indexes for table `loan_request`
--
ALTER TABLE `loan_request`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `group_id` (`group_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `my_group`
--
ALTER TABLE `my_group`
  ADD PRIMARY KEY (`group_id`),
  ADD KEY `group_admin_id` (`group_admin_id`);

--
-- Indexes for table `my_savings`
--
ALTER TABLE `my_savings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `group_id` (`group_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`notification_id`),
  ADD KEY `target_user_id` (`target_user_id`),
  ADD KEY `target_group_id` (`target_group_id`);

--
-- Indexes for table `password_reset_tokens`
--
ALTER TABLE `password_reset_tokens`
  ADD PRIMARY KEY (`email`);

--
-- Indexes for table `polls`
--
ALTER TABLE `polls`
  ADD PRIMARY KEY (`poll_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `polls_vote`
--
ALTER TABLE `polls_vote`
  ADD PRIMARY KEY (`vote_id`),
  ADD UNIQUE KEY `unique_vote` (`poll_id`,`user_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `questions`
--
ALTER TABLE `questions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `reactions`
--
ALTER TABLE `reactions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `question_id` (`question_id`),
  ADD KEY `reply_id` (`reply_id`);

--
-- Indexes for table `replies`
--
ALTER TABLE `replies`
  ADD PRIMARY KEY (`id`),
  ADD KEY `question_id` (`question_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `savings`
--
ALTER TABLE `savings`
  ADD PRIMARY KEY (`savings_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `transaction_info`
--
ALTER TABLE `transaction_info`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `group_id` (`group_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `withdrawal`
--
ALTER TABLE `withdrawal`
  ADD PRIMARY KEY (`withdrawal_id`),
  ADD KEY `user_id` (`user_id`),
  ADD KEY `group_id` (`group_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `contact_us`
--
ALTER TABLE `contact_us`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `expert_team`
--
ALTER TABLE `expert_team`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `group_membership`
--
ALTER TABLE `group_membership`
  MODIFY `membership_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=31;

--
-- AUTO_INCREMENT for table `investments`
--
ALTER TABLE `investments`
  MODIFY `investment_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `investment_returns`
--
ALTER TABLE `investment_returns`
  MODIFY `return_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `leaderboard`
--
ALTER TABLE `leaderboard`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT for table `loan_repayments`
--
ALTER TABLE `loan_repayments`
  MODIFY `repayment_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `loan_request`
--
ALTER TABLE `loan_request`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

--
-- AUTO_INCREMENT for table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `my_group`
--
ALTER TABLE `my_group`
  MODIFY `group_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=20;

--
-- AUTO_INCREMENT for table `my_savings`
--
ALTER TABLE `my_savings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `notification_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=87;

--
-- AUTO_INCREMENT for table `polls`
--
ALTER TABLE `polls`
  MODIFY `poll_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=26;

--
-- AUTO_INCREMENT for table `polls_vote`
--
ALTER TABLE `polls_vote`
  MODIFY `vote_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `questions`
--
ALTER TABLE `questions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `reactions`
--
ALTER TABLE `reactions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=47;

--
-- AUTO_INCREMENT for table `replies`
--
ALTER TABLE `replies`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `savings`
--
ALTER TABLE `savings`
  MODIFY `savings_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT for table `transaction_info`
--
ALTER TABLE `transaction_info`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- AUTO_INCREMENT for table `withdrawal`
--
ALTER TABLE `withdrawal`
  MODIFY `withdrawal_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `group_membership`
--
ALTER TABLE `group_membership`
  ADD CONSTRAINT `group_membership_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`),
  ADD CONSTRAINT `group_membership_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `investments`
--
ALTER TABLE `investments`
  ADD CONSTRAINT `investments_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);

--
-- Constraints for table `investment_returns`
--
ALTER TABLE `investment_returns`
  ADD CONSTRAINT `investment_returns_ibfk_1` FOREIGN KEY (`investment_id`) REFERENCES `investments` (`investment_id`);

--
-- Constraints for table `leaderboard`
--
ALTER TABLE `leaderboard`
  ADD CONSTRAINT `leaderboard_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`) ON DELETE CASCADE;

--
-- Constraints for table `loan_repayments`
--
ALTER TABLE `loan_repayments`
  ADD CONSTRAINT `loan_repayments_ibfk_1` FOREIGN KEY (`loan_id`) REFERENCES `loan_request` (`id`);

--
-- Constraints for table `loan_request`
--
ALTER TABLE `loan_request`
  ADD CONSTRAINT `loan_request_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `loan_request_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);

--
-- Constraints for table `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`),
  ADD CONSTRAINT `messages_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `my_group`
--
ALTER TABLE `my_group`
  ADD CONSTRAINT `my_group_ibfk_1` FOREIGN KEY (`group_admin_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `my_savings`
--
ALTER TABLE `my_savings`
  ADD CONSTRAINT `my_savings_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `my_savings_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `notifications`
--
ALTER TABLE `notifications`
  ADD CONSTRAINT `notifications_ibfk_1` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `notifications_ibfk_2` FOREIGN KEY (`target_group_id`) REFERENCES `my_group` (`group_id`) ON DELETE CASCADE;

--
-- Constraints for table `polls`
--
ALTER TABLE `polls`
  ADD CONSTRAINT `polls_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);

--
-- Constraints for table `polls_vote`
--
ALTER TABLE `polls_vote`
  ADD CONSTRAINT `polls_vote_ibfk_1` FOREIGN KEY (`poll_id`) REFERENCES `polls` (`poll_id`),
  ADD CONSTRAINT `polls_vote_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `questions`
--
ALTER TABLE `questions`
  ADD CONSTRAINT `questions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `reactions`
--
ALTER TABLE `reactions`
  ADD CONSTRAINT `reactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `reactions_ibfk_2` FOREIGN KEY (`question_id`) REFERENCES `questions` (`id`),
  ADD CONSTRAINT `reactions_ibfk_3` FOREIGN KEY (`reply_id`) REFERENCES `replies` (`id`);

--
-- Constraints for table `replies`
--
ALTER TABLE `replies`
  ADD CONSTRAINT `replies_ibfk_1` FOREIGN KEY (`question_id`) REFERENCES `questions` (`id`),
  ADD CONSTRAINT `replies_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `savings`
--
ALTER TABLE `savings`
  ADD CONSTRAINT `savings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `savings_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);

--
-- Constraints for table `transaction_info`
--
ALTER TABLE `transaction_info`
  ADD CONSTRAINT `transaction_info_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `transaction_info_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);

--
-- Constraints for table `withdrawal`
--
ALTER TABLE `withdrawal`
  ADD CONSTRAINT `withdrawal_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  ADD CONSTRAINT `withdrawal_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `my_group` (`group_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
