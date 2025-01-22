<?php
// Retrieving records from database
require_once "global.php";

class Get extends GlobalMethods{
    private $pdo;

    public function __construct(\PDO $pdo){
        $this->pdo = $pdo;
    }

    public function executeQuery($sql){
        $data = array(); //place to store records retrieved for db
        $errmsg = ""; //initialized error message variable
        $code = 0; //initialize status code variable

        try{
            if($result = $this->pdo->query($sql)->fetchAll()){ //retrieved records from db, returns false if no records found
                foreach($result as $record){
                    array_push($data, $record);
                }
                $code = 200;
                $result = null;
                return array("code"=>$code, "data"=>$data);
            }
            else{
                //if no record found, assign corresponding values to error messages/status
                $errmsg = "No records found";
                $code = 404;
            }
        }
        catch(\PDOException $e){
            //PDO errors, mysql errors
            $errmsg = $e->getMessage();
            $code = 403;
        }
        return array("code"=>$code, "errmsg"=>$errmsg);
    }

    //Enter the public function below
    public function get_records($table, $condition=null){
        $sqlString = "SELECT * FROM $table";
        if($condition != null){
            $sqlString .= " WHERE " . $condition;
        }
        
        $result = $this->executeQuery($sqlString);

        if($result['code']==200){
            return $this->sendPayload($result['data'], "success", "Successfully retrieved records.", $result['code']);
        }
        
        return $this->sendPayload(null, "failed", "Failed to retrieve records.", $result['code']);
    }

    public function get_events() {
        $response = $this->get_records('events', null);
        return $response;
    }   
    
    public function get_events_userside() {
        $condition = "archived = 0"; // Condition to filter out archived events
        $response = $this->get_records('events', $condition);
        return $response;
    }  

    public function get_info() {
        $sql = "SELECT * FROM participants WHERE isArchived = 0"; // Select non-archived participants
        $stmt = $this->pdo->prepare($sql);
        
        try {
            $stmt->execute();
            $participants = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $participants;
        } catch (PDOException $e) {
            // Handle any potential errors
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }    
    
    public function get_attendees($eventId) {
        try {
            // Prepare SQL statement to fetch attendance data for the specified event ID
            $sql = "SELECT * FROM attendance WHERE event_id = ?";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([$eventId]);
            
            // Fetch all attendance records for the specified event ID
            $attendanceData = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Return the fetched attendance data
            return $attendanceData;
        } catch(PDOException $e) {
            // Handle any potential errors
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }


    public function get_attendance_for_event($eventId) {
        try {
            // Prepare SQL statement to fetch attendance data for the specified event ID
            $sql = "SELECT * FROM attendance WHERE event_id = ?";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([$eventId]);
            
            // Fetch all attendance records for the specified event ID
            $attendanceData = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Return the fetched attendance data
            return $attendanceData;
        } catch(PDOException $e) {
            // Handle any potential errors
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function get_participant_by_name($name) {
        try {
            $sql = "SELECT p.first_name, p.last_name, e.event_name, e.event_date, e.event_location, e.organizer
                    FROM participants p
                    JOIN attendance a ON p.participant_id = a.participant_id
                    JOIN events e ON a.event_id = e.event_id
                    WHERE p.first_name LIKE ? OR p.last_name LIKE ?";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute(["%$name%", "%$name%"]);
            
            $participants = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $participantName = $row['first_name'] . ' ' . $row['last_name'];
                if (!isset($participants[$participantName])) {
                    $participants[$participantName] = [
                        'first_name' => $row['first_name'],
                        'last_name' => $row['last_name'],
                        'events' => []
                    ];
                }
                $participants[$participantName]['events'][] = [
                    'event_name' => $row['event_name'],
                    'event_date' => $row['event_date'],
                    'event_location' => $row['event_location'], // Include event location
                    'organizer' => $row['organizer'] // Include organizer
                ];
            }
            
            return array_values($participants);
        } catch(PDOException $e) {
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function get_events_with_participant_counts() {
        try {
            $sql = "SELECT e.event_id, e.event_name, e.event_date, e.event_location, e.organizer, COUNT(a.participant_id) AS participant_count
                    FROM events e
                    LEFT JOIN attendance a ON e.event_id = a.event_id
                    GROUP BY e.event_id";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute();

            $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return $events;
        } catch(PDOException $e) {
            // Handle any potential errors
            return [
                "status" => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    public function get_participants(){
        $response = $this->get_records('participants',null);
        return $response;
    }
    
    public function get_totalEvents(){
        $response = $this->get_records('events',null);
        return $response;
    }

    // Inside the Get class
    public function getMostParticipatedEvent() {
        try {
            $query = "SELECT e.event_name, COUNT(a.participant_id) as participant_count 
                    FROM events e 
                    JOIN attendance a ON e.event_id = a.event_id 
                    GROUP BY e.event_name 
                    ORDER BY participant_count DESC 
                    LIMIT 1";
            $stmt = $this->pdo->prepare($query);
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result;
        } catch (PDOException $e) {
            // Handle database connection errors
            return array('error' => 'Database error: ' . $e->getMessage());
        }
    }
}
