<?php

class Login
{
    private $error = "";

    public function evaluate($data)
    {
        // Sanitize and validate email
        $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->error .= "Invalid email format<br>";
            return $this->error;
        }

        $password = $data['password']; // Do not escape password, as we'll use hashing
        
        // Query to fetch user by email
        $query = "SELECT * FROM users WHERE email = :email LIMIT 1";

        $DB = new Database();
        $result = $DB->read($query, ['email' => $email]);

        if ($result) {
            $row = $result[0];

            // Verify password using hash
            if (password_verify($password, $row['password'])) {
                // Create session and cookie
                $_SESSION['mybook_userid'] = $row['userid'];

                // Set cookies for "remember me" functionality
                if (!empty($data['remember_me'])) {
                    $token = bin2hex(random_bytes(16)); // Generate a secure token
                    setcookie("login_token", $token, time() + (86400 * 30), "/"); // 30 days expiry
                    // Save the token in the database
                    $update_query = "UPDATE users SET token = :token WHERE userid = :userid";
                    $DB->read($update_query, ['token' => $token, 'userid' => $row['userid']]);
                }
            } else {
                $this->error .= "Wrong password<br>";
            }
        } else {
            $this->error .= "No such email was found<br>";
        }

        return $this->error;
    }

    public function check_login($id)
    {
        $DB = new Database();

        if (is_numeric($id)) {
            // Query to fetch user by ID
            $query = "SELECT * FROM users WHERE userid = :userid LIMIT 1";
            $result = $DB->read($query, ['userid' => $id]);

            if ($result) {
                return $result[0];
            }
        } elseif (isset($_COOKIE['login_token'])) {
            // Check for valid cookie token
            $token = $_COOKIE['login_token'];
            $query = "SELECT * FROM users WHERE token = :token LIMIT 1";
            $result = $DB->read($query, ['token' => $token]);

            if ($result) {
                $_SESSION['mybook_userid'] = $result[0]['userid'];
                return $result[0];
            }
        }

        // Redirect to login if authentication fails
        header("Location: login.php");
        die;
    }
}
