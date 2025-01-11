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

class UserHandler {
    private $conn;

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function register($data) {
        // Ensure the keys in the data array match your database columns
        $query = "INSERT INTO users 
            (firstname, lastname, date_of_birth, gender, home_address, contact_number, email, password, role) 
            VALUES 
            (:firstname, :lastname, :date_of_birth, :gender, :home_address, :contact_number, :email, :password, :role)";
        
        try {
            $stmt = $this->conn->prepare($query);
            // Map frontend variables correctly
            $stmt->bindParam(':firstname', $data['firstName']);
            $stmt->bindParam(':lastname', $data['lastName']);
            $stmt->bindParam(':date_of_birth', $data['dob']);
            $stmt->bindParam(':gender', $data['gender']);
            $stmt->bindParam(':home_address', $data['homeAddress']);
            $stmt->bindParam(':contact_number', $data['contactNumber']);
            $stmt->bindParam(':email', $data['email']);
            
            // Hash the password
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
            $stmt->bindParam(':password', $hashedPassword);
    
            // Set user role as 'user'
            $role = 'user';
            $stmt->bindParam(':role', $role);
    
            // Execute query
            if ($stmt->execute()) {
                return ['status' => true, 'message' => 'User registered successfully'];
            }
            return ['status' => false, 'message' => 'Failed to register user'];
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
                // Generate a token (optional)
                $token = bin2hex(random_bytes(16));

                // Check user role and set the correct dashboard
                if ($user['role'] === 'admin') {
                    $dashboard = 'Admin Dashboard';
                } elseif ($user['role'] === 'user') {
                    $dashboard = 'User Dashboard';
                } else {
                    // Deny login if role is unknown
                    return ['status' => false, 'message' => 'Access denied for this role'];
                }

                return [
                    'status' => true,
                    'message' => 'Login successful',
                    'dashboard' => $dashboard,
                    'token' => $token,
                    'user' => [
                        'id' => $user['id'],
                        'firstname' => $user['firstname'],
                        'lastname' => $user['lastname'],
                        'email' => $user['email'],
                        'role' => $user['role']
                    ]
                ];
            }

            return ['status' => false, 'message' => 'Invalid email or password'];
        } catch (PDOException $e) {
            return ['status' => false, 'message' => $e->getMessage()];
        }
    }
}

// Route user actions
$userHandler = new UserHandler();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'register') {
        echo json_encode($userHandler->register($data));
    } elseif ($action === 'login') {
        echo json_encode($userHandler->login($data));
    } else {
        echo json_encode(['status' => false, 'message' => 'Invalid action']);
    }
}
?>
