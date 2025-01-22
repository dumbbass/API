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

    // Fetch appointments for a specific patient
    public function getAppointments($patient_id) {
        return $this->get_records('appointments', 'patient_id = '.$patient_id);
    }

    // Fetch patient info
    public function getPatientInfo($id) {
        return $this->get_records('patients', 'id = '.$id);
    }

    public function getPatientUserInfo($id) {
        return $this->get_records('user', 'id = '.$id);
    }

    // Fetch all doctors
    public function getDoctors() {
        return $this->get_records('doctors');
    }

        // Fetch appointments with doctor details (new method)
    public function getAppointmentsWithDoctorInfo($patient_id) {
        // SQL query to fetch appointments along with doctor details
        $sql = "
            SELECT a.appointment_id, a.patient_id, a.doctor_id, a.appointment_date, a.appointment_time, a.purpose, a.status,
                    d.firstname AS doctor_firstname, d.lastname AS doctor_lastname
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.doctor_id
            WHERE a.patient_id = :patient_id
        ";

        // Prepare and execute the query
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':patient_id', $patient_id, PDO::PARAM_INT);
        $stmt->execute();

        // Fetch the results
        $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($appointments) {
            // Return the appointments along with doctor info
            return $this->sendPayload($appointments, "success", "Successfully retrieved appointments with doctor information.", 200);
        } else {
            // Return a failure response if no appointments found
            return $this->sendPayload(null, "failed", "No appointments found for this patient.", 404);
        }
    }

        // Fetch appointments for a specific doctor with patient names
        public function getDoctorsPatients($doctorId) {
            // SQL query to fetch appointments along with patient details (names)
            $sql = "
            SELECT a.appointment_id, a.patient_id, a.doctor_id, a.appointment_date, a.appointment_time, a.purpose, a.status,
                p.firstname AS patient_firstname, p.lastname AS patient_lastname, p.gender AS gender
            FROM appointments a
            LEFT JOIN patients p ON a.patient_id = p.patient_id
            WHERE a.doctor_id = :doctor_id
            ";
    
            // Prepare and execute the query
            $stmt = $this->pdo->prepare($sql);
            $stmt->bindParam(':doctor_id', $doctorId, PDO::PARAM_INT);
            $stmt->execute();
    
            // Fetch the results
            $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            // Check if appointments are found
            if ($appointments) {
                // Return appointments with patient details
                return $this->sendPayload($appointments, "success", "Successfully retrieved appointments with patient information.", 200);
            } else {
                // Return failure response if no appointments are found
                return $this->sendPayload(null, "failed", "No appointments found for this doctor.", 404);
            }
        }
}
