<?php
require_once '../Routing/routes.php';
require_once '../Connection/connection.php';

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");
header('Content-Type: application/json');

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

    public function getUserProfile($userId) {
        if (!is_numeric($userId) || $userId <= 0) {
            return [
                'status' => false,
                'message' => 'Invalid user ID'
            ];
        }

        $query = "SELECT firstname, lastname, date_of_birth, gender, home_address, contact_number, email FROM users WHERE id = :id";
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':id', $userId);
            $stmt->execute();

            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                return [
                    'status' => true,
                    'user' => $user
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'User not found'
                ];
            }
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
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

    //scheduling lineeeee.........

    public function getDoctorsWithAdminRole() {
        $query = "SELECT id, firstname, lastname, email FROM users WHERE role = 'admin'";
    
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
    
            $doctors = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            if ($doctors) {
                // Handle null values
                foreach ($doctors as &$doctor) {
                    $doctor['firstname'] = $doctor['firstname'] ?? 'Unknown';
                    $doctor['lastname'] = $doctor['lastname'] ?? 'Unknown';
                }
    
                return [
                    'status' => true,
                    'doctors' => $doctors
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'No doctors found with the admin role'
                ];
            }
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
    }    
    

     // Function to schedule an appointment
     public function scheduleAppointment($data) {
        session_start();  // Start session to access user data
        $patientId = $_SESSION['user_id'];  // Current logged-in patient's ID
        $doctorId = $data['doctor_id'];
        $appointmentDate = $data['appointment_date'];
        $purpose = $data['purpose'];
    
        // Database connection
        $db = new Database();
        $conn = $db->getConnection();
    
        // SQL query to insert the appointment
        $query = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, purpose, status, created_at, updated_at) 
                  VALUES (?, ?, ?, ?, 'pending', NOW(), NOW())";
    
        // Prepare and bind the statement
        $stmt = $conn->prepare($query);
        $stmt->bindParam("iiss", $patientId, $doctorId, $appointmentDate, $purpose);  
    
        // Execute the query
        if ($stmt->execute()) {
            return ['status' => true, 'message' => 'Appointment scheduled successfully'];
        } else {
            return ['status' => false, 'message' => 'Failed to schedule appointment: ' . $stmt->errorInfo()[2]];
        }
    }
    
    public function setAppointmentTime($appointmentId, $time) {
        $db = new Database();
        $conn = $db->getConnection();
    
        $query = "UPDATE appointments SET appointment_time = ?, status = 'accepted', updated_at = NOW() WHERE appointment_id = ?";
        $stmt = $conn->prepare($query);
        $stmt->bindParam("si", $time, $appointmentId);  
    
        if ($stmt->execute()) {
            return ['status' => true, 'message' => 'Appointment time set successfully'];
        } else {
            return ['status' => false, 'message' => 'Failed to set appointment time: ' . $stmt->errorInfo()[2]];
        }
    }    

    public function updateAppointmentStatus($data) {
        $appointment_id = $data['appointment_id'];
        $status = $data['status']; // 'Approved' or 'Rescheduled'
        $appointment_time = isset($data['appointment_time']) ? $data['appointment_time'] : null;
    
        if (empty($appointment_id) || empty($status)) {
            return [
                'status' => false,
                'message' => 'Appointment ID and status are required.'
            ];
        }
    
        // Prepare the query to update the appointment
        if ($status === 'Approved') {
            $query = "UPDATE appointments SET status = ?, appointment_time = ? WHERE id = ?";
            $stmt = $this->conn->prepare($query);
            // Bind params: string for status, string for appointment_time, integer for appointment_id
            $stmt->bindParam('ssi', $status, $appointment_time, $appointment_id);
        } else if ($status === 'Rescheduled') {
            $query = "UPDATE appointments SET status = ?, appointment_time = NULL WHERE id = ?";
            $stmt = $this->conn->prepare($query);
            // Bind params: string for status, integer for appointment_id
            $stmt->bindParam('si', $status, $appointment_id);
        }
    
        try {
            if ($stmt->execute()) {
                return [
                    'status' => true,
                    'message' => 'Appointment updated successfully.'
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'Failed to update appointment.'
                ];
            }
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
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
    } elseif ($action === 'scheduleAppointment') {
        session_start();  // Start session to get logged-in user

        // Automatically get the patient ID from the session
        $patientId = $_SESSION['user_id'] ?? null;
        $doctorId = $_POST['doctor_id'] ?? null;
        $appointmentDate = $_POST['appointment_date'] ?? null;
        $purpose = $_POST['purpose'] ?? null;

        // Check if the patient is logged in and all required fields are provided
        if ($patientId && $doctorId && $appointmentDate && $purpose) {
            // Prepare the data to be passed to the handler
            $response = $userHandler->scheduleAppointment([
                'doctor_id' => $doctorId,
                'appointment_date' => $appointmentDate,
                'purpose' => $purpose
            ]);
            echo json_encode($response);
        } else {
            echo json_encode(['status' => false, 'message' => 'All fields are required']);
        }
    } else {
        echo json_encode(['status' => false, 'message' => 'Invalid action']);
    }
}

// Only one block to handle GET requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['action'])) {
        $action = $_GET['action']; // Get the action parameter from the query string
        
        // Debug log: print the action value
        error_log("Received action: $action"); // This will log to the PHP error log
        
        // Check for each action and handle accordingly
        if ($action === 'getDoctorsWithAdminRole') {
            $response = $userHandler->getDoctorsWithAdminRole();
            echo json_encode($response);
        } elseif ($action === 'getUserProfile') {
            $userId = $_GET['id'] ?? null;
            if ($userId) {
                $response = $userHandler->getUserProfile($userId);
                echo json_encode($response);
            } else {
                echo json_encode(['status' => false, 'message' => 'User ID is required']);
            }
        } else {
            echo json_encode(['status' => false, 'message' => 'Invalid action']);
        }
    } else {
        echo json_encode(['status' => false, 'message' => 'Action parameter is missing']);
    }
}


?>
