<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Start output buffering to prevent accidental output
ob_start();

// Allow requests from any origin
header('Access-Control-Allow-Origin: *');

// Allow specific HTTP methods
header('Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE');

// Allow specific headers
header('Access-Control-Allow-Headers: Content-Type, X-Auth-Token, Origin, Authorization');

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
switch ($_SERVER['REQUEST_METHOD']) {
    // Pull records from the database
    // Handle GET requests
    case 'GET':
        switch ($request[0]) {
            case "getevent":
                echo json_encode($get->get_events()); // Call the get_events() method
                break;

            case "getevent_user":
                echo json_encode($get->get_events_userside());
                break;

            case "getattendees":
                if (isset($request[1])) {
                    $eventId = $request[1]; // Extract the event ID from the request
                    echo json_encode($get->get_attendance_for_event($eventId)); // Call the get_attendance_for_event() method with the event ID
                } else {
                    // Handle the case where the event ID is not provided
                    echo "Event ID not provided";
                    http_response_code(400); // Bad request status code
                }
                break;

            case "getinfo":
                echo json_encode($get->get_info()); // Call the get_events() method
                break;

            case 'home_totalParticipants':
                echo json_encode($get->get_participants());
                break;

            case 'home_totalEvents':
                echo json_encode($get->get_totalEvents());
                break;

            case 'mostparticipatedevent':
                echo json_encode($get->getMostParticipatedEvent());
                break;

            case "getparticipant":
                if (isset($_GET['name'])) {
                    $participantName = $_GET['name'];
                    echo json_encode($get->get_participant_by_name($participantName));
                } else {
                    echo "Participant name not provided";
                    http_response_code(400); // Bad request status code
                }
                break;

            case "get_events_with_participant_counts":
                echo json_encode($get->get_events_with_participant_counts());
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
        switch ($request[0]) {
            case 'login':
                // Call the login method of the Post class
                echo json_encode($post->login($data));
                break;

            case 'submitfeedback':
                // Return JSON-encoded data for adding employees
                echo json_encode($post->submit_feedback($data));
                break;

            case 'sendemail':
                // Call the sendEmail method of the Post class
                echo json_encode($post->sendEmail($data));
                break;

            case 'attendance': // Handle attendance request
                echo json_encode($post->submit_attendance($data)); // Call method to submit attendance
                break;

            case 'addevent':
                // Return JSON-encoded data for adding events
                echo json_encode($post->add_event($data));
                break;

            case 'editparticipant':
                // Return JSON-encoded data for adding events
                echo json_encode($post->edit_participant($data));
                break;

            case 'archiveparticipant':
                echo json_encode($post->archiveParticipant($data));
                break;

            case 'update_event':
                if (isset($request[1])) {
                    $eventId = $request[1]; // Extract the event ID from the request
                    echo json_encode($post->update_event($eventId, $data));
                } else {
                    // Handle the case where the event ID is not provided
                    echo "Event ID not provided";
                    http_response_code(400); // Bad request status code
                }
                break;

            case 'update_participant':
                if (isset($request[1])) {
                    $participantId = $request[1]; // Extract the participant ID from the request
                    // Assuming $data contains the updated participant information
                    echo json_encode($post->update_participant($participantId, $data));
                } else {
                    // Handle the case where the participant ID is not provided
                    echo "Participant ID not provided";
                    http_response_code(400); // Bad request status code
                }
                break;

            case 'archive_event':
                if (isset($request[1])) {
                    $eventId = $request[1]; // Extract the event ID from the request
                    echo json_encode($post->archive_event($eventId)); // Pass the event ID to the archive_event method
                } else {
                    // Handle the case where the event ID is not provided
                    echo "Event ID not provided";
                    http_response_code(400); // Bad request status code
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

// End output buffering and send output
ob_end_flush();
?>
