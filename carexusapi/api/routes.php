<?php   
    /**
 * API Endpoint Router
 *
 * This PHP script serves as a simple API endpoint router, handling GET and POST requests for specific resources.
 *
 *
 * Usage:
 * 1. Include this script in your project.
 * 2. Define resource-specific logic in the 'get.php' and 'post.php' modules.
 * 3. Send requests to the appropriate endpoints defined in the 'switch' cases below.
 */

    // Allow requests from any origin
    header('Access-Control-Allow-Origin: *');
    
    // Allow specific HTTP methods
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE');
    
    // Allow specific headers
    header('Access-Control-Allow-Headers: Content-Type, X-Auth-Token, Origin, Authorization');

    // Set Content-Type header to application/json for all responses
    header('Content-Type: application/json');
    
    // Handle preflight requests
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']))
            header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']))
            header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
    
        exit(0);
    }
    
    // Include required modules
    require_once "./modules/get.php";
    require_once "./modules/post.php";
    require_once "./config/database.php";
    
    $con = new Connection();
    $pdo = $con->connect();
    
    // Initialize Get and Post objects
    $get = new Get($pdo);
    $post = new Post($pdo);
    
    // Check if 'request' parameter is set in the request
    if (isset($_REQUEST['request'])) {
        // Split the request into an array based on '/'
        $request = explode('/', $_REQUEST['request']);
    } else {
        // If 'request' parameter is not set, return a 404 response
        echo "Not Found";
        http_response_code(404);
        exit();
    }

    // Handle requests based on HTTP method
    switch($_SERVER['REQUEST_METHOD']){
        // Pull records from the database
        // Handle GET requests
        case 'GET':
            switch($request[0]){
                // Get all appointments for a patient
                case 'getAppointments':
                    if (isset($_GET['patient_id'])) {
                        // Fetch appointments with doctor information
                        echo json_encode($get->getAppointmentsWithDoctorInfo($_GET['patient_id']));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Missing patient ID"));
                    }
                break;

                // Get patient information
                case 'getPatients':
                    if (isset($_GET['id'])) {
                        echo json_encode($get->get_records('patients', 'id = '.$_GET['id']));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Missing patient ID"));
                    }
                break;                

                case 'getPatientsUser':
                    if (isset($_GET['id'])) {
                        echo json_encode($get->get_records('users', 'id = '.$_GET['id']));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Missing patient ID"));
                    }
                break;

                // Get list of doctors
                case 'getDoctors':
                    echo json_encode($get->get_records('doctors'));
                break;

                case 'getDoctorInfo':
                    if (isset($_GET['id'])) {
                        echo json_encode($get->get_records('doctors', 'id = '.$_GET['id']));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Missing doctors ID"));
                    }
                break;

                case 'getDoctorsPatients':
                    if (isset($_GET['doctor_id'])) {
                        echo json_encode($get->getDoctorsPatients($_GET['doctor_id']));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Missing doctor ID"));
                    }
                break;
                    
                default:
                    // Return a 403 response for unsupported requests
                    echo "This is forbidden";
                    http_response_code(403);
                break;
            }
            break;

            
        // Handle POST requests    
        case 'POST':
            // Retrieves JSON-decoded data from php://input using file_get_contents
            $data = json_decode(file_get_contents("php://input"));
            switch($request[0]){
                // Schedule an appointment
                case 'scheduleAppointment':
                    if (isset($data)) {
                        echo json_encode($post->add_appointment($data));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Invalid data"));
                    }
                break;

                case 'login':
                    if (isset($data)) {
                        echo json_encode($post->login($data));
                    } else {
                        echo json_encode(array("code" => 400, "message" => "Invalid data"));
                    }
                break;
                

                default:
                    // Return a 403 response for unsupported requests
                    echo "This is forbidden";
                    http_response_code(403);
                    break;
            }
            break;
        default:
            // Return a 404 response for unsupported HTTP methods
            echo "Method not available";
            http_response_code(404);
        break;
}
    
    

?>