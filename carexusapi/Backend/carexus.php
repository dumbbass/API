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

        $query = "SELECT firstname, lastname, date_of_birth, gender, home_address, contact_number, email, age, birthplace, nationality, religion, civil_status FROM users WHERE id = :id";
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
        $firstName = $data['firstName'];
        $lastName = $data['lastName'];
        $dob = $data['dob'];
        $gender = $data['gender'];
        $homeAddress = $data['homeAddress'];
        $contactNumber = $data['contactNumber'];
        $email = $data['email'];
        $password = password_hash($data['password'], PASSWORD_DEFAULT);
        $birthplace = $data['birthplace'];
        $nationality = $data['nationality'];
        $religion = $data['religion'];
        $civilStatus = $data['civilStatus'];
        $age = $data['age'];
    
        // Check if height and weight are set, otherwise use 0
        $height = isset($data['height']) ? $data['height'] : 0;
        $weight = isset($data['weight']) ? $data['weight'] : 0;
        
        $medications = $data['medications'];
        $role = 'user';
    
        try {
            // Validate required fields (including new fields)
            if (empty($firstName) || empty($lastName) || empty($dob) || empty($gender) || empty($homeAddress) || empty($contactNumber) || empty($email) || empty($password) || empty($medications) || empty($birthplace) || empty($nationality) || empty($religion) || empty($civilStatus) || empty($age)) {
                echo json_encode(['status' => false, 'message' => 'All fields are required']);
                return;
            }
    
            // Insert into users table with new fields
            $query = "INSERT INTO users (firstname, lastname, date_of_birth, gender, home_address, contact_number, email, password, role, birthplace, nationality, religion, civil_status, age) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $this->conn->prepare($query);
            $stmt->execute([$firstName, $lastName, $dob, $gender, $homeAddress, $contactNumber, $email, $password, $role, $birthplace, $nationality, $religion, $civilStatus, $age]);
    
            // Get the last inserted user ID
            $userId = $this->conn->lastInsertId();
    
            // Insert into patients table with new fields
            $query = "INSERT INTO patients (id, firstname, lastname, gender, email, height, weight, medications, birthplace, nationality, religion, civil_status, age, created_at, updated_at) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())";
            $stmt = $this->conn->prepare($query);
            $stmt->execute([$userId, $firstName, $lastName, $gender, $email, $height, $weight, $medications, $birthplace, $nationality, $religion, $civilStatus, $age]);
    
            echo json_encode(['status' => true, 'message' => 'User registered successfully']);
        } catch (Exception $e) {
            error_log('Registration error: ' . $e->getMessage());
            echo json_encode(['status' => false, 'message' => 'Failed to register user: ' . $e->getMessage()]);
        }
    }    
    
    public function login($data) {
        $query = "SELECT id, firstname, lastname, email, role, password, height, weight, medications FROM users WHERE email = :email";

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
    
    public function getUsers() {
        $query = "SELECT id, firstname, lastname, gender, email,  contact_number, home_address, birthplace, age, nationality, religion, civil_status FROM users";
        
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->execute();
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return [
                'status' => true,
                'users' => $users
            ];
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
    }

    public function getAppointments($patientId) {
        $query = "
            SELECT 
                a.appointment_id, 
                a.appointment_date, 
                a.appointment_time, 
                a.purpose, 
                a.status, 
                d.firstname AS doctor_firstname, 
                d.lastname AS doctor_lastname
            FROM 
                appointments a
            JOIN 
                doctors d ON a.doctor_id = d.doctor_id
            WHERE 
                a.patient_id = :patientId
        ";

        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':patientId', $patientId, PDO::PARAM_INT);
            $stmt->execute();
            $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return [
                'status' => true,
                'appointments' => $appointments
            ];
        } catch (PDOException $e) {
            return [
                'status' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
    }

    public function updateUserProfile($data) {
        $userId = $data['id'];
        $firstname = $data['firstname'];
        $lastname = $data['lastname'];
        $email = $data['email'];
        $homeAddress = $data['home_address'];
        $contactNumber = $data['contact_number'];
        $height = isset($data['height']) ? $data['height'] : 0; // Default to 0 if not provided
        $weight = isset($data['weight']) ? $data['weight'] : 0; // Default to 0 if not provided
        $medications = $data['medications'];
        $gender = $data['gender'];
        $dob = $data['dob'];
        $birthplace = $data['birthplace'];
        $age = $data['age'];
        $nationality = $data['nationality'];
        $religion = $data['religion'];
        $civilStatus = $data['civil_status']; 
        
        



        if (!is_numeric($userId) || $userId <= 0) {
            return [
                'status' => false,
                'message' => 'Invalid user ID'
            ];
        }

        $query = "UPDATE users SET firstname = :firstname, lastname = :lastname, email = :email, home_address = :homeAddress, contact_number = :contactNumber, height = :height, weight = :weight, medications = :medications, gender = :gender, dob = :dob, birthplace = :birthplace, age = :age, nationality = :nationality, religion = :religion, civil_status = :civilStatus WHERE id = :id";
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':id', $userId);
            $stmt->bindParam(':firstname', $firstname);
            $stmt->bindParam(':lastname', $lastname);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':homeAddress', $homeAddress);
            $stmt->bindParam(':contactNumber', $contactNumber);
            $stmt->bindParam(':height', $height);
            $stmt->bindParam(':weight', $weight);
            $stmt->bindParam(':medications', $medications);
            $stmt->bindParam(':gender', $gender);
            $stmt->bindParam(':dob', $dob);
            $stmt->bindParam(':birthplace', $birthplace);
            $stmt->bindParam(':age', $age);
            $stmt->bindParam(':nationality', $nationality);
            $stmt->bindParam(':religion', $religion);
            $stmt->bindParam(':civilStatus', $civilStatus);
            
            $stmt->execute();

            return [
                'status' => true,
                'message' => 'User profile updated successfully'
            ];
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
        // Decode incoming JSON data
        $data = json_decode(file_get_contents('php://input'), true);

        // Validate required fields
        $requiredFields = [
            'firstName', 'lastName', 'dob', 'gender', 
            'homeAddress', 'contactNumber', 'email', 
            'password', 'medications'
        ];

        // Check for non-numeric fields (string fields)
        foreach ($requiredFields as $field) {
            if (empty($data[$field]) && !isset($data[$field])) {
                echo json_encode(['status' => false, 'message' => "$field is required"]);
                return;
            }
        }

        // Special validation for numeric fields (height and weight)
        if (!isset($data['height'])) {
            echo json_encode(['status' => false, 'message' => "height is required"]);
            return;
        }
        if (!isset($data['weight'])) {
            echo json_encode(['status' => false, 'message' => "weight is required"]);
            return;
        }

        // Call the register method with the full data
        $userHandler->register($data);
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
    } elseif ($action === 'updateUserProfile') {
        $data = json_decode(file_get_contents('php://input'), true);
        $response = $userHandler->updateUserProfile($data);
        echo json_encode($response);
    } else {
        echo json_encode(['status' => false, 'message' => 'Invalid action']);
    }
}


// Only one block to handle GET requests

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['action'])) {
        $action = $_GET['action'];

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
        } elseif ($action === 'getUsers') {
            $response = $userHandler->getUsers();
            echo json_encode($response);
        } elseif ($action === 'getAppointments') {
            $patientId = $_GET['patient_id'] ?? null;
            if ($patientId) {
                $response = $userHandler->getAppointments($patientId);
                echo json_encode($response);
            } else {
                echo json_encode(['status' => false, 'message' => 'Patient ID is required']);
            }
        } else {
            echo json_encode(['status' => false, 'message' => 'Action parameter is missing']);
        }
    }
}

