<?php
// POST Method

require_once "global.php"; 
require_once 'C:/xampp/htdocs/CEPA-Main/vendor/autoload.php';

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
    public function login($data) {
        // Extract ID and password from the request data
        $id = isset($data->id) ? $data->id : null;
        $password = isset($data->password) ? $data->password : null;

        // Check if ID and password are provided
        if (!$id || !$password) {
            // Return error response if ID or password is missing
            return array('error' => 'ID and password are required');
        }

        // Perform the authentication logic by querying the database
        // Check if the provided ID and password match any record in the admin_login table
        $stmt = $this->pdo->prepare("SELECT * FROM admin_login WHERE id = ? AND password = ?");
        $stmt->execute([$id, $password]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($admin) {
            // Admin found, generate a dynamic secret key
    // Generate a dynamic secret key
    $secret_key = bin2hex(random_bytes(32)); // Generate a 32-byte (256-bit) key and convert it to hexadecimal format

    // Define the algorithm
    $algorithm = 'HS256'; // Example algorithm, you can choose the appropriate one based on your requirements

    // Generate JWT token with 1-day expiration
    $payload = array(
        "id" => $admin['id'],
        "exp" => time() + (60 * 60 * 24) // Token expiration time (1 day)
    );
    $jwt = JWT::encode($payload, $secret_key, $algorithm);

    // Return success response with JWT token
    return array('success' => 'Login successful', 'token' => $jwt);
        } else {
            // No admin found with the provided ID and password, return error response
            return array('error' => 'Invalid ID or password');
        }
    }

    

    public function add_event($data) {
        $sql = "INSERT INTO events(event_name, event_date, event_location, organizer, description) VALUES (?,?,?,?,?)";
    
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
    
                $data->event_name,
                $data->event_date,
                $data->event_location,
                $data->organizer,
                $data->description

            ]);
            return $this->sendPayload(null, "success", "Successfully created a new event.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
        }
        return $this->sendPayload(null, "failed", $errmsg, 400);
    }
    

    public function submit_feedback($data) {
        $sql = "INSERT INTO feedback(q1_answer, q2_answer, q3_answer, q4_answer, q5_answer, feedback) 
                VALUES (?, ?, ?, ?, ?, ?)";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
                $data->q1_answer,
                $data->q2_answer,
                $data->q3_answer,
                $data->q4_answer,
                $data->q5_answer,
                $data->feedback
            ]);
            
            // Return a JSON response indicating success
            return json_encode(["status" => "success", "message" => "Successfully created a new feedback record."]);
        } catch(\PDOException $e) {
            // Return a JSON response indicating failure with error message
            return json_encode(["status" => "failed", "message" => $e->getMessage()]);
        }
    }
    public function edit_participant($data) {
        $sql = "UPDATE participants SET first_name=?, last_name=?, email=?, phone_number=?, address=? WHERE participant_id=?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
                $data->participant_id, // Assuming participant_id is included in $data
                $data->first_name,
                $data->last_name,
                $data->email,
                $data->phone_number,
                $data->address
            ]);
            return $this->sendPayload(null, "success", "Successfully updated participant information.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
            return $this->sendPayload(null, "failed", $errmsg, 400);
        }
    }

      //Send Email no template
    //  public function sendEmail($data){
    //     // Check if $data is null
    //     if ($data === null) {
    //         return ['success' => false, 'message' => 'Data is null'];
    //     }
    
    //     // Debug autoload
    //     $mail = new PHPMailer(true);
    
    //     try {
    //         // Configure SMTP settings
    //         $mail->isSMTP();                                            //Send using SMTP
    //         $mail->Host       = 'smtp.gmail.com';                       //Set the SMTP server to send through
    //         $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
    //         $mail->Username   = 'cepa.appdev@gmail.com';                //SMTP username
    //         $mail->Password   = 'iiot dgrb rlxw mcas';                  //SMTP password
    //         $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
    //         $mail->Port       = 465;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`
    
    //         // Set email content
    //         $mail->setFrom('cepa.appdev@gmail.com', 'CEPA');
    
    //         // Check if $data->to is set
    //         if (isset($data->to)) {
    //             $mail->addAddress($data->to);
    //         } else {
    //             return ['success' => false, 'message' => 'Recipient email is not provided'];
    //         }
    
    //         // Check if $data->subject is set
    //         if (isset($data->subject)) {
    //             $mail->Subject = $data->subject;
    //         } else {
    //             return ['success' => false, 'message' => 'Email subject is not provided'];
    //         }
    
    //         // Check if $data->message is set
    //         if (isset($data->message)) {
    //             $mail->Body = $data->message;
    //             $mail->isHTML(true); // Set email as HTML
    //         } else {
    //             return ['success' => false, 'message' => 'Email message is not provided'];
    //         }
    
    //         // Send email
    //         $mail->send();
    //         return ['success' => true, 'message' => 'Email sent successfully'];
    //     } catch (Exception $e) {
    //         return ['success' => false, 'message' => 'Failed to send email: ' . $mail->ErrorInfo];
    //     }
    // }
    
// Enter public function below
public function sendEmail($data, $template = 'default') {
    // Check if $data is null
    if ($data === null) {
        return ['success' => false, 'message' => 'Data is null'];
    }

    // Extract eventId from qrCodeImageUrl
    $pattern = '/attendance\/(\d+)/';
    preg_match($pattern, $data->qrCodeImageUrl, $matches);
    $eventId = isset($matches[1]) ? $matches[1] : null;

    // Check if eventId is extracted successfully
    if ($eventId === null) {
        return ['success' => false, 'message' => 'Event ID not found in QR code URL'];
    }

    // Construct the QR code data
    $qrCodeData = 'http://localhost/attendance/' . $eventId;

    // Generate the QR code using the builder
    $qrCode = Builder::create()
        ->writer(new PngWriter())
        ->data($qrCodeData)
        ->encoding(new Encoding('UTF-8'))
        ->errorCorrectionLevel(ErrorCorrectionLevel::High)
        ->size(150)
        ->margin(10)
        ->validateResult(false)
        ->build();

    // Get the QR code image data
    $qrCodeContent = $qrCode->getString();
    $qrCodeImageUrl = 'data:image/png;base64,' . base64_encode($qrCodeContent);

    // Define the path for the temporary QR code image
    $tempDir = 'C:\xampp\htdocs\CEPA-Main\temp';
    $tempImagePath = $tempDir . '\qr_code.png';

    // Ensure the temp directory exists
    if (!is_dir($tempDir)) {
        mkdir($tempDir, 0777, true);
    }

    // Save the QR code image to a file
    file_put_contents($tempImagePath, $qrCodeContent);

    // Initialize PHPMailer
    $mail = new PHPMailer(true);

    try {
        // Configure SMTP settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'cepa.appdev@gmail.com';
        $mail->Password   = 'iiot dgrb rlxw mcas';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port       = 465;

        // Set sender
        $mail->setFrom('cepa.appdev@gmail.com', 'CEPA');

        // Set recipient
        if (isset($data->to)) {
            $mail->addAddress($data->to);
        } else {
            return ['success' => false, 'message' => 'Recipient email is not provided'];
        }

        // Set subject
        if (isset($data->subject)) {
            $mail->Subject = $data->subject;
        } else {
            return ['success' => false, 'message' => 'Email subject is not provided'];
        }

        // Load email content template
        $templateFile = __DIR__ . '/../template/' . $template . '.php';
        if (!file_exists($templateFile)) {
            return ['success' => false, 'message' => 'Template not found'];
        }

        // Prepare template data
        $templateData = [
            'message' => $data->message, // Pass the message from $data to the template
            'qrCodeData' => $qrCodeData // Pass other necessary data to the template
        ];

        // Load the template and replace placeholders with actual data
        ob_start();
        extract($templateData);
        include $templateFile;
        $emailContent = ob_get_clean();
        
        // var_dump($emailContent);

        // Set email content
        $mail->isHTML(true); 
        $mail->Body = $emailContent;

        // Attach the QR code image
        $mail->AddEmbeddedImage($tempImagePath, 'qr_code_image');

        // Send email
        $mail->send();
        return ['success' => true, 'message' => 'Email sent successfully'];

        // Delete the temporary QR code image
        if (file_exists($tempImagePath)) {
            unlink($tempImagePath);
        }
    } catch (Exception $e) {
        // Log error
        error_log('Failed to send email: ' . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to send email: ' . $e->getMessage()];
    }
}




    public function submit_attendance($data) {
        // Check if participant exists, if not, insert them
        $participantId = $this->insertParticipant($data);
    
        // Construct the SQL query to insert attendance data
        $sql = "INSERT INTO attendance (event_id, participant_id, attendance_date, l_name, f_name, address, email, p_number) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
                $data->event_id,
                $participantId,
                $data->attendance_date, // Add attendance date to the execution array
                $data->l_name,
                $data->f_name,
                $data->address,
                $data->email,
                $data->p_number
            ]);
            
            // Return a success message in JSON format
            return json_encode([
                "status" => "success",
                "message" => "Successfully submitted attendance."
            ]);
        } catch(\PDOException $e) {
            // Return an error message in JSON format
            return json_encode([
                "status" => "error",
                "message" => $e->getMessage()
            ]);
        }
    }
    
    private function insertParticipant($data) {
        // Check if the participant already exists by name and email
        $existingParticipant = $this->getParticipantByNameAndEmail($data->f_name, $data->l_name, $data->email);
    
        if ($existingParticipant) {
            // Participant already exists, return their ID
            return $existingParticipant['participant_id'];
        } else {
            // Participant doesn't exist, insert them and return their ID
            $sql = "INSERT INTO participants (first_name, last_name, email, phone_number, address) 
                    VALUES (?, ?, ?, ?, ?)";
            
            try {
                $statement = $this->pdo->prepare($sql);
                $statement->execute([
                    $data->f_name,
                    $data->l_name,
                    $data->email,
                    $data->p_number,
                    $data->address
                ]);
        
                // Return the auto-generated participant ID
                return $this->pdo->lastInsertId();
            } catch(\PDOException $e) {
                // Handle participant insertion error
                // For simplicity, you can return null here or handle the error as needed
                return null;
            }
        }
    }
    
    private function getParticipantByNameAndEmail($firstName, $lastName, $email) {
        // Check if the participant already exists by name and email
        $sql = "SELECT participant_id FROM participants WHERE first_name = ? AND last_name = ? AND email = ?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([$firstName, $lastName, $email]);
            return $statement->fetch(PDO::FETCH_ASSOC);
        } catch(\PDOException $e) {
            // Handle error
            return null;
        }
    }

    public function update_event($eventId, $data) {
        $sql = "UPDATE events SET event_name=?, event_date=?, event_location=?, organizer=?, description=? WHERE event_id=?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
                $data->event_name,
                $data->event_date,
                $data->event_location,
                $data->organizer,
                $data->description,
                $eventId // Use the provided event ID parameter
            ]);
            return $this->sendPayload(null, "success", "Successfully updated the event.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
        }
        return $this->sendPayload(null, "failed", $errmsg, 400);
    }

    public function archiveParticipant($data) {
        $sql = "UPDATE participants SET isArchived = 1 WHERE participant_id = ?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([$data->participant_id]);
            return $this->sendPayload(null, "success", "Successfully archived participant.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
            return $this->sendPayload(null, "failed", $errmsg, 400);
        }
    }

    public function archive_event($event_id) {
        $sql = "UPDATE events SET archived=1 WHERE event_id=?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([$event_id]);
            return $this->sendPayload(null, "success", "Successfully archived the event.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
        }
        return $this->sendPayload(null, "failed", $errmsg, 400);
    }

    public function update_participant($participantId, $data) {
        // Ensure no trailing comma in the SQL query
        $sql = "UPDATE participants SET first_name=?, last_name=?, email=?, phone_number=? WHERE participant_id=?";
        
        try {
            $statement = $this->pdo->prepare($sql);
            $statement->execute([
                $data->first_name,
                $data->last_name,
                $data->email,
                $data->phone_number,
                $participantId // Use the provided participant ID parameter
            ]);
            return $this->sendPayload(null, "success", "Successfully updated the participant.", 200);
        } catch (\PDOException $e) {
            $errmsg = $e->getMessage();
            return $this->sendPayload(null, "failed", $errmsg, 400);
        }
    }
}