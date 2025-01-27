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
        
            // Determine role
            $role = 'user';  // Default role
            if ($data['role'] === 'admin') {
                $role = 'admin';
            }
            $stmt->bindParam(':role', $role);
        
            // Execute query
            if ($stmt->execute()) {
                // After successful registration, assign role to user (e.g., if it's an admin, insert into doctor table)
                $userId = $this->conn->lastInsertId();
                return $this->assignRoleToUser($userId, $data['firstName'], $data['lastName'], $data['gender'], $data['email'], $role);
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

    public function assignRoleToUser($userId, $firstName, $lastName, $gender, $email, $role) {
        // Database connection
        $db = new Database();
        $conn = $db->getConnection();
    
        // Check if the role is doctor or patient
        if ($role === 'admin') {
            // Insert doctor details into doctors table (admin is treated as doctor)
            $query = "INSERT INTO doctors (id, first_name, last_name, gender, email, created_at, updated_at) 
                      VALUES (?, ?, ?, ?, ?, NOW(), NOW())";
    
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $userId, PDO::PARAM_INT);
            $stmt->bindParam(2, $firstName, PDO::PARAM_STR);
            $stmt->bindParam(3, $lastName, PDO::PARAM_STR);
            $stmt->bindParam(4, $gender, PDO::PARAM_STR);
            $stmt->bindParam(5, $email, PDO::PARAM_STR);
    
            if ($stmt->execute()) {
                return ['status' => true, 'message' => 'Admin assigned as doctor successfully'];
            } else {
                return ['status' => false, 'message' => 'Failed to assign admin as doctor'];
            }
        } elseif ($role === 'patient') {
            // Insert patient details into patients table
            $query = "INSERT INTO patients (id, first_name, last_name, gender, email, created_at, updated_at) 
                      VALUES (?, ?, ?, ?, ?, NOW(), NOW())";
    
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $userId, PDO::PARAM_INT);
            $stmt->bindParam(2, $firstName, PDO::PARAM_STR);
            $stmt->bindParam(3, $lastName, PDO::PARAM_STR);
            $stmt->bindParam(4, $gender, PDO::PARAM_STR);
            $stmt->bindParam(5, $email, PDO::PARAM_STR);
    
            if ($stmt->execute()) {
                return ['status' => true, 'message' => 'Patient assigned successfully'];
            } else {
                return ['status' => false, 'message' => 'Failed to assign patient'];
            }
        } else {
            return ['status' => false, 'message' => 'Invalid role'];
        }
    }    
   


    //scheduling lineeeee.........

    public function getDoctors() {
        $query = "SELECT doctor_id, firstname, lastname, email FROM doctors";
        
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
                    'message' => 'No doctors found'
                ];
            }
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
    }
    
    public function getPatients() {
        // Modify query to include user_id (assuming a relation exists)
        $query = "
            SELECT 
                patients.patient_id, 
                patients.firstname, 
                patients.lastname, 
                patients.email, 
                users.id 
            FROM patients
            JOIN users ON users.email = patients.email"; // Assuming 'email' is the link between patients and users
    
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
    
            $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            if ($patients) {
                // Handle null values and ensure consistency
                foreach ($patients as &$patient) {
                    $patient['firstname'] = $patient['firstname'] ?? 'Unknown';
                    $patient['lastname'] = $patient['lastname'] ?? 'Unknown';
                }
    
                return [
                    'status' => true,
                    'patients' => $patients
                ];
            } else {
                return [
                    'status' => false,
                    'message' => 'No patients found'
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
    // Fetching the patient and doctor details from the request
    $patientId = $data['patient_id'];  // Patient ID added here
    $doctorId = $data['doctor_id'];
    $appointmentDate = $data['appointment_date'];
    $purpose = $data['purpose'];

    // Database connection
    $db = new Database();
    $conn = $db->getConnection();

    // Step 1: Check if the doctor has an available appointed_time
    $query = "SELECT appointed_time FROM doctors WHERE doctor_id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(1, $doctorId, PDO::PARAM_INT);
    $stmt->execute();
    $doctor = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$doctor || !$doctor['appointed_time']) {
        return [
            'status' => false,
            'message' => 'Doctor does not have an appointed time set or is unavailable'
        ];
    }

    // Step 2: Validate the appointment date availability
    $query = "SELECT * FROM appointments WHERE doctor_id = ? AND appointment_date = ? AND status != 'cancelled'";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(1, $doctorId, PDO::PARAM_INT);
    $stmt->bindParam(2, $appointmentDate, PDO::PARAM_STR);
    $stmt->execute();
    $existingAppointment = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($existingAppointment) {
        return [
            'status' => false,
            'message' => 'Doctor is already booked for this date'
        ];
    }

    // Step 3: Insert the new appointment with patient_id
    $query = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, purpose, status, created_at, updated_at) 
              VALUES (?, ?, ?, ?, 'pending', NOW(), NOW())";

    $stmt = $conn->prepare($query);
    $stmt->bindParam(1, $patientId, PDO::PARAM_INT);
    $stmt->bindParam(2, $doctorId, PDO::PARAM_INT);
    $stmt->bindParam(3, $appointmentDate, PDO::PARAM_STR);
    $stmt->bindParam(4, $purpose, PDO::PARAM_STR);

    if ($stmt->execute()) {
        return [
            'status' => true,
            'message' => 'Appointment scheduled successfully'
        ];
    } else {
        return [
            'status' => false,
            'message' => 'Failed to schedule appointment: ' . $stmt->errorInfo()[2]
        ];
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

// Ensure the action is passed through the URL query string (GET method)
$action = $_GET['action'] ?? null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($action === 'register') {
        // Get incoming POST data
        $data = json_decode(file_get_contents('php://input'), true);

        // Extract user registration details
        $firstName = $data['firstName'];
        $lastName = $data['lastName'];
        $dob = $data['dob'];
        $gender = $data['gender'];
        $homeAddress = $data['homeAddress'];
        $contactNumber = $data['contactNumber'];
        $email = $data['email'];
        $password = password_hash($data['password'], PASSWORD_DEFAULT);  // Secure password storage
        
        // Set the role to 'user' by default
        $role = 'user';

        // Database connection
        $db = new Database();
        $conn = $db->getConnection();

        // Start a transaction to ensure both operations are atomic
        $conn->beginTransaction();

        try {
            // Step 1: Insert user into the 'users' table with role set to 'user'
            $query = "INSERT INTO users (firstname, lastname, date_of_birth, gender, home_address, contact_number, email, password, role) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($query);
            $stmt->execute([$firstName, $lastName, $dob, $gender, $homeAddress, $contactNumber, $email, $password, $role]);

            // Get the last inserted user ID (which will be used as the user_id in the patients table)
            $userId = $conn->lastInsertId();

            // Step 2: Insert into the 'patients' table as this is a user (not an admin)
            $query = "INSERT INTO patients (id, firstname, lastname, gender, email, created_at, updated_at) 
                      VALUES (?, ?, ?, ?, ?, NOW(), NOW())";
            $stmt = $conn->prepare($query);
            $stmt->execute([$userId, $firstName, $lastName, $gender, $email]);

            // Commit the transaction after both inserts
            $conn->commit();

            // Return success message
            echo json_encode(['status' => true, 'message' => 'User registered successfully']);
        } catch (Exception $e) {
            // Rollback transaction in case of error
            $conn->rollBack();
            echo json_encode(['status' => false, 'message' => 'Failed to register user: ' . $e->getMessage()]);
        }
    } elseif ($action === 'login') {
        // Login functionality remains the same...
        $data = json_decode(file_get_contents('php://input'), true);

        // Get email and password from the incoming data
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;

        // Validate input data
        if ($email && $password) {
            // Database connection
            $db = new Database();
            $conn = $db->getConnection();

            // Query to check if the user exists
            $query = "SELECT id, firstname, lastname, password, role FROM users WHERE email = ?";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $email);
            $stmt->execute();

            // Debug: Check if the query returns any result
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                // Debugging - if no user found
                echo json_encode(['status' => false, 'message' => 'User not found']);
                return;
            }

            // Verify password (hash comparison, assuming you hash passwords when storing)
            if (password_verify($password, $user['password'])) {
                // Password is correct, return user details and role
                echo json_encode([
                    'status' => true,
                    'message' => 'Login successful',
                    'user' => [
                        'id' => $user['id'],
                        'firstName' => $user['firstname'],
                        'lastName' => $user['lastname'],
                        'role' => $user['role']
                    ]
                ]);
            } else {
                // Debugging - if the password doesn't match
                echo json_encode(['status' => false, 'message' => 'Invalid credentials']);
            }
        } else {
            echo json_encode(['status' => false, 'message' => 'Email and password are required']);
        }

        } elseif ($action === 'scheduleAppointment') {
            $data = json_decode(file_get_contents('php://input'), true);
        
            $patientId = $data['patient_id'];
            $doctorId = $data['doctor_id'];
            $appointmentDate = $data['appointment_date'];
            $purpose = $data['purpose'];
        
            $db = new Database();
            $conn = $db->getConnection();
        
            // ✅ Validate if the doctor exists
            $query = "SELECT doctor_id FROM doctors WHERE doctor_id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $doctorId, PDO::PARAM_INT);
            $stmt->execute();
            $doctorExists = $stmt->fetch(PDO::FETCH_ASSOC);
        
            if (!$doctorExists) {
                echo json_encode(['status' => false, 'message' => 'Invalid doctor ID. Doctor not found.']);
                return;
            }
        
            // ✅ Validate if the patient exists
            $query = "SELECT patient_id FROM patients WHERE patient_id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $patientId, PDO::PARAM_INT);
            $stmt->execute();
            $patientExists = $stmt->fetch(PDO::FETCH_ASSOC);
        
            if (!$patientExists) {
                echo json_encode(['status' => false, 'message' => 'Invalid patient ID. Patient not found.']);
                return;
            }
        
            // ✅ Check if the doctor is available on the selected date
            $query = "SELECT * FROM appointments WHERE doctor_id = ? AND appointment_date = ? AND status != 'cancelled'";
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $doctorId, PDO::PARAM_INT);
            $stmt->bindParam(2, $appointmentDate, PDO::PARAM_STR);
            $stmt->execute();
            $existingAppointment = $stmt->fetch(PDO::FETCH_ASSOC);
        
            if ($existingAppointment) {
                echo json_encode(['status' => false, 'message' => 'Doctor is already booked for this date.']);
                return;
            }
        
            // ✅ Insert the appointment if both doctor and patient exist
            $query = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, purpose, status, created_at, updated_at) 
                      VALUES (?, ?, ?, ?, 'pending', NOW(), NOW())";
        
            $stmt = $conn->prepare($query);
            $stmt->bindParam(1, $patientId, PDO::PARAM_INT);
            $stmt->bindParam(2, $doctorId, PDO::PARAM_INT);
            $stmt->bindParam(3, $appointmentDate, PDO::PARAM_STR);
            $stmt->bindParam(4, $purpose, PDO::PARAM_STR);
        
            if ($stmt->execute()) {
                echo json_encode(['status' => true, 'message' => 'Appointment scheduled successfully']);
            } else {
                echo json_encode(['status' => false, 'message' => 'Failed to schedule appointment: ' . $stmt->errorInfo()[2]]);
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
        if ($action === 'getDoctors') {
            $response = $userHandler->getDoctors();
            echo json_encode($response);

        } elseif ($action === 'getUserProfile') {
            $userId = $_GET['id'] ?? null;
            if ($userId) {
                $response = $userHandler->getUserProfile($userId);
                echo json_encode($response);
            } else {
                echo json_encode(['status' => false, 'message' => 'User ID is required']);
            }

        } elseif ($action === 'getPatients') {  // New condition for getting patients
            $response = $userHandler->getPatients(); // Call the new function to get patients
            echo json_encode($response);  // Return the response as JSON

    } else {
        echo json_encode(['status' => false, 'message' => 'Action parameter is missing']);
    }
}
}


?>
