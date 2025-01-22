<?php
// POST Method

require_once "global.php"; 
require_once 'C:/xampp/htdocs/API/carexusapi/api/vendor/autoload.php';
// require_once "/home/u475125807/domains/itcepacommunity.com/public_html/api/vendor/autoload.php";


// Import PHPMailer classes
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;
use Firebase\JWT\JWT;
use chillerlan\QRCode\QROptions;
use Endroid\QrCode\Color\Color;
use Endroid\QrCode\Encoding\Encoding;
use Endroid\QrCode\ErrorCorrectionLevel;
use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Label\Label;
use Endroid\QrCode\Logo\Logo;
use Endroid\QrCode\RoundBlockSizeMode;
use Endroid\QrCode\Writer\PngWriter;
use Endroid\QrCode\Writer\ValidationException;


class Post extends GlobalMethods{
    private $pdo;

    public function __construct(\PDO $pdo){
        $this->pdo = $pdo;
    }
    
    /**
     * Add a new with the provided data.
     *
     * @param array|object $data
     *   The data representing the new.
     *
     * @return array|object
     *   The added data.
     */

     //Enter the public function below
    
     // Add a new appointment
        public function add_appointment($data) {
        $sql = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, purpose) 
                VALUES (:patient_id, :doctor_id, :appointment_date, :appointment_time, :purpose)";
    
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':patient_id', $data->patient_id);
        $stmt->bindParam(':doctor_id', $data->doctor_id);
        $stmt->bindParam(':appointment_date', $data->appointment_date);
        $stmt->bindParam(':appointment_time', $data->appointment_time);
        $stmt->bindParam(':purpose', $data->purpose);
    
        try {
            $stmt->execute();
    
            // Prepare the response using sendPayload method from GlobalMethods
            $appointmentData = array(
                "patient_id" => $data->patient_id,
                "doctor_id" => $data->doctor_id,
                "appointment_date" => $data->appointment_date,
                "appointment_time" => $data->appointment_time,
                "purpose" => $data->purpose
            );
            
            return $this->sendPayload($appointmentData, "success", "Appointment scheduled successfully", 200);
        } catch (\PDOException $e) {
            // Handle error and return failure response
            return $this->sendPayload(null, "failed", $e->getMessage(), 500);
        }
    }
    

    public function login($data) {
        $query = "SELECT id, firstname, lastname, email, role, password FROM users WHERE email = :email";
        
        try {
            $stmt = $this->pdo->prepare($query);
            $stmt->bindParam(':email', $data->email);  // Change $data['email'] to $data->email
            $stmt->execute();
    
            // Fetch data as an object
            $user = $stmt->fetch(PDO::FETCH_OBJ); // Fetch as object
    
            if ($user && password_verify($data->password, $user->password)) {  // Access properties using ->, not []
                // Generate a token (optional)
                $token = bin2hex(random_bytes(16));
    
                // Check user role and set the correct dashboard
                if ($user->role === 'admin') {
                    $dashboard = 'Admin Dashboard';
                } elseif ($user->role === 'user') {
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
                        'id' => $user->id,
                        'firstname' => $user->firstname,
                        'lastname' => $user->lastname,
                        'email' => $user->email,
                        'role' => $user->role
                    ]
                ];
            }
    
            return ['status' => false, 'message' => 'Invalid email or password'];
        } catch (PDOException $e) {
            return ['status' => false, 'message' => "Error: " . $e->getMessage()];
        }
    }
    


    public function assignRoleToUser($userId, $firstName, $lastName, $gender, $email, $role) {
        // Check if the role is doctor or patient
        if ($role === 'admin') {
            // Insert admin details into the doctors table (admin is treated as doctor)
            $query = "INSERT INTO doctors (id, first_name, last_name, gender, email, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, ?, NOW(), NOW())";
        
            $stmt = $this->pdo->prepare($query);
            $stmt->bindParam(1, $userId, PDO::PARAM_INT);
            $stmt->bindParam(2, $firstName, PDO::PARAM_STR);
            $stmt->bindParam(3, $lastName, PDO::PARAM_STR);
            $stmt->bindParam(4, $gender, PDO::PARAM_STR);
            $stmt->bindParam(5, $email, PDO::PARAM_STR);
        
            try {
                $stmt->execute();
                return ['status' => true, 'message' => 'Admin assigned as doctor successfully'];
            } catch (\PDOException $e) {
                return ['status' => false, 'message' => 'Failed to assign admin as doctor: ' . $e->getMessage()];
            }
        } elseif ($role === 'patient') {
            // Insert patient details into patients table
            $query = "INSERT INTO patients (id, first_name, last_name, gender, email, created_at, updated_at) 
                        VALUES (?, ?, ?, ?, ?, NOW(), NOW())";
        
            $stmt = $this->pdo->prepare($query);
            $stmt->bindParam(1, $userId, PDO::PARAM_INT);
            $stmt->bindParam(2, $firstName, PDO::PARAM_STR);
            $stmt->bindParam(3, $lastName, PDO::PARAM_STR);
            $stmt->bindParam(4, $gender, PDO::PARAM_STR);
            $stmt->bindParam(5, $email, PDO::PARAM_STR);
        
            try {
                $stmt->execute();
                return ['status' => true, 'message' => 'Patient assigned successfully'];
            } catch (\PDOException $e) {
                return ['status' => false, 'message' => 'Failed to assign patient: ' . $e->getMessage()];
            }
        } else {
            return ['status' => false, 'message' => 'Invalid role'];
        }
    }
}