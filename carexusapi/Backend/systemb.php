<?php
require_once '../Routing/routes.php';
require_once '../Connection/connection.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    // Set CORS headers for preflight request
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    exit(0);  // Exit after responding to OPTIONS request
}

$routes = new Routes();
$data = json_decode(file_get_contents("php://input"), true);
$action = $_GET['action'] ?? '';

class AdminHandler {
    private $conn;

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function register($data) {
        $query = "INSERT INTO users 
            (firstname, lastname, date_of_birth, gender, home_address, contact_number, email, password, role) 
            VALUES 
            (:firstname, :lastname, :date_of_birth, :gender, :home_address, :contact_number, :email, :password, 'admin')";

        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':firstname', $data['firstname']);
            $stmt->bindParam(':lastname', $data['lastname']);
            $stmt->bindParam(':date_of_birth', $data['date_of_birth']);
            $stmt->bindParam(':gender', $data['gender']);
            $stmt->bindParam(':home_address', $data['home_address']);
            $stmt->bindParam(':contact_number', $data['contact_number']);
            $stmt->bindParam(':email', $data['email']);
            $stmt->bindParam(':password', $hashedPassword);
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
            
            if ($stmt->execute()) {
                return ['status' => true, 'message' => 'Admin registered successfully'];
            }
            return ['status' => false, 'message' => 'Failed to register admin'];
        } catch (PDOException $e) {
            return ['status' => false, 'message' => $e->getMessage()];
        }
    }

    public function login($data) {
        $query = "SELECT id, firstname, lastname, email, role, password FROM users WHERE email = :email";
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':email', $data['email']);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($data['password'], $user['password'])) {
                if ($user['role'] === 'admin') {
                    return [
                        'status' => true,
                        'dashboard' => 'Admin Dashboard',
                        'user' => $user
                    ];
                }
                return ['status' => false, 'message' => 'Access denied for non-admin'];
            }
            return ['status' => false, 'message' => 'Invalid email or password'];
        } catch (PDOException $e) {
            return ['status' => false, 'message' => $e->getMessage()];
        }
    }
}

// Route admin actions
$adminHandler = new AdminHandler();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'register') {
        echo json_encode($adminHandler->register($data));
    } elseif ($action === 'login') {
        echo json_encode($adminHandler->login($data));
    } else {
        echo json_encode(['status' => false, 'message' => 'Invalid action']);
    }
}
?>
