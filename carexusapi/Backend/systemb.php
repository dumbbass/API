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

    // Function to check if the email already exists
    public function checkEmail($email) {
        try {
            $query = "SELECT COUNT(*) as count FROM users WHERE email = :email";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            // If email exists, return true, else false
            if ($result['count'] > 0) {
                return ['exists' => true];
            } else {
                return ['exists' => false];
            }
        } catch (PDOException $e) {
            return ['status' => false, 'message' => $e->getMessage()];
        }
    }

    // Function for registration
    public function register($data) {
        // Check if the email already exists
        $emailCheck = $this->checkEmail($data['email']);
        if ($emailCheck['exists']) {
            return ['status' => false, 'message' => 'Email already exists'];
        }

        // If email is unique, proceed with registration
        $query = "INSERT INTO users 
            (firstname, lastname, date_of_birth, gender, home_address, contact_number, email, password, role) 
            VALUES 
            (NULL, NULL, NULL, NULL, NULL, NULL, :email, :password, 'admin')";
    
        try {
            $stmt = $this->conn->prepare($query);
            
            // Bind email and password
            $stmt->bindParam(':email', $data['email']);
            $stmt->bindParam(':password', $hashedPassword);
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
            
            // Execute the query
            if ($stmt->execute()) {
                return ['status' => true, 'message' => 'Admin registered successfully'];
            }
            return ['status' => false, 'message' => 'Failed to register admin'];
        } catch (PDOException $e) {
            return ['status' => false, 'message' => $e->getMessage()];
        }
    }

    // Function for login
    public function login($data) {
        $query = "SELECT id, firstname, lastname, email, role, password FROM users WHERE email = :email";
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':email', $data['email']);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
            // Check if user exists and password is correct
            if ($user && password_verify($data['password'], $user['password'])) {
                // Only allow login if the user is an admin
                if ($user['role'] === 'admin') {
                    return [
                        'status' => true,
                        'dashboard' => 'Admin Dashboard',
                        'user' => $user
                    ];
                } else {
                    // Deny login for non-admin users (e.g., users with role 'user')
                    return ['status' => false, 'message' => 'Access denied for non-admin users'];
                }
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

// Handle GET request for email check
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $action === 'checkEmail') {
    $email = $_GET['email'] ?? '';
    if ($email) {
        echo json_encode($adminHandler->checkEmail($email));
    } else {
        echo json_encode(['status' => false, 'message' => 'Email parameter is required']);
    }
}
?>
