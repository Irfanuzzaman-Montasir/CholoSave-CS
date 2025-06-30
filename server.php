<?php
require 'vendor/autoload.php';
require 'db.php'; // Include your database connection file

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Http\HttpServer;
use Ratchet\Server\IoServer;
use Ratchet\WebSocket\WsServer;

class Chat implements MessageComponentInterface {
    protected $clients;

    public function __construct() {
        $this->clients = new \SplObjectStorage;
    }

    public function onOpen(ConnectionInterface $conn) {
        $this->clients->attach($conn);
        echo "New connection! ({$conn->resourceId})\n";
    }

    public function onMessage(ConnectionInterface $from, $msg) {
        global $conn; // Use the database connection from db.php

        $data = json_decode($msg, true);

        // Save the message to the database
        $stmt = $conn->prepare("INSERT INTO messages (group_id, user_id, message) VALUES (?, ?, ?)");
        if (!$stmt) {
            echo "Database error: " . $conn->error . "\n";
            return;
        }

        $stmt->bind_param("iis", $data['group_id'], $data['user_id'], $data['message']);
        $stmt->execute();
        $stmt->close();

        // Broadcast the message to all connected clients
        foreach ($this->clients as $client) {
            $client->send($msg);
        }
    }

    public function onClose(ConnectionInterface $conn) {
        $this->clients->detach($conn);
        echo "Connection {$conn->resourceId} has disconnected\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e) {
        echo "An error has occurred: {$e->getMessage()}\n";
        $conn->close();
    }
}

// Create and run the WebSocket server
$server = IoServer::factory(
    new HttpServer(
        new WsServer(
            new Chat()
        )
    ),
    8080
);

echo "WebSocket server running on ws://localhost:8080\n";
$server->run();
