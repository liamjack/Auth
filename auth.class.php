<?php

class auth
{	
	public $mysqli;
	public $errormsg;
	public $successmsg;
	
	// DB Configuration
	
	private $db_host = "******";
	private $db_user = "******";
	private $db_pass = "******";
	private $db_name = "******";
	
	// Functions
	
	function __construct()
	{
		// Start a new MySQLi Connection
	
		$this->mysqli = new mysqli($this->db_host, $this->db_user, $this->db_pass, $this->db_name);
	}
	
	/*
	* Log user in via MySQL Database
	* @param string $username
	* @param string $password
	* @return boolean
	*/
	
	function login($username, $password)
	{
		if(!isset($_COOKIE["auth_session"]))
		{
			$attcount = $this->getattempt($_SERVER['REMOTE_ADDR']);
			
			if($attcount >= 5)
			{
				$this->errormsg[] = "You have been temporarily locked out !";
				$this->errormsg[] = "Please wait 30 minutes.";
				
				return false;
			}
			else 
			{
				// Input verification :
			
				if(strlen($username) == 0) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				elseif(strlen($username) > 30) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				elseif(strlen($username) < 3) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				elseif(strlen($password) == 0) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				elseif(strlen($password) > 30) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				elseif(strlen($password) < 5) { $this->errormsg[] = "Username / Password is invalid !"; return false; }
				else 
				{
					// Input is valid
				
					$password = $this->hashpass($password);
				
					$query = $this->mysqli->prepare("SELECT isactive FROM users WHERE username = ? AND password = ?");
					$query->bind_param("ss", $username, $password);
					$query->bind_result($isactive);
					$query->execute();
					$query->store_result();
					$count = $query->num_rows;
					$query->fetch();
					$query->close();
				
					if($count == 0)
					{
						// Username and / or password are incorrect
					
						$this->errormsg[] = "Username / Password is incorrect !";
						
						$this->addattempt($_SERVER['REMOTE_ADDR']);
						
						$attcount = $attcount + 1;
						$remaincount = 5 - $attcount;
						
						$this->errormsg[] = "$remaincount attempts remaining.";
						
						return false;
					}
					else 
					{
						// Username and password are correct
						
						if($isactive == "0")
						{
							// Account is not activated
							
							$this->errormsg[] = "Account is not activated !";
							
							return false;
						}
						else
						{
							// Account is activated
						
							$this->newsession($username);				
					
							$this->successmsg[] = "You are now logged in !";
							
							return true;
						}
					}
				}
			}
		}
		else 
		{
			// User is already logged in
			
			$this->errormsg[] = "You are already logged in !";
			
			return false;
		}
	}
	
	/*
	* Register a new user into the database
	* @param string $username
	* @param string $password
	* @param string $verifypassword
	* @param string $email
	* @return boolean
	*/
	
	function register($username, $password, $verifypassword, $email)
	{
		if(!isset($_COOKIE["auth_session"]))
		{
			// Input Verification :
		
			if(strlen($username) == 0) { $this->errormsg[] = "Username field is empty !"; }
			elseif(strlen($username) > 30) { $this->errormsg[] = "Username is too long !"; }
			elseif(strlen($username) < 3) { $this->errormsg[] = "Username is too short !"; }
			if(strlen($password) == 0) { $this->errormsg[] = "Password field is empty !"; }
			elseif(strlen($password) > 30) { $this->errormsg[] = "Password is too long !"; }
			elseif(strlen($password) < 5) { $this->errormsg[] = "Password is too short !"; }
			elseif($password !== $verifypassword) { $this->errormsg[] = "Passwords don't match !"; }
			elseif(strstr($password, $username)) { $this->errormsg[] = "Password cannot contain the username !"; }
			if(strlen($email) == 0) { $this->errormsg[] = "Email field is empty !"; }
			elseif(strlen($email) > 100) { $this->errormsg[] = "Email is too long !"; }
			elseif(strlen($email) < 5) { $this->errormsg[] = "Email is too short !"; }
			elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) { $this->errormsg[] = "Email address is invalid !"; }
		
			if(count($this->errormsg) == 0)
			{
				// Input is valid
			
				$query = $this->mysqli->prepare("SELECT * FROM users WHERE username=?");
				$query->bind_param("s", $username);
				$query->execute();
				$query->store_result();
				$count = $query->num_rows;
				$query->close();
			
				if($count != 0)
				{
					// Username already exists
				
					$this->errormsg[] = "Username is already taken !";
					
					return false;
				}
				else 
				{
					// Username is not taken
					
					$query = $this->mysqli->prepare("SELECT * FROM users WHERE email=?");
					$query->bind_param("s", $email);
					$query->execute();
					$query->store_result();
					$count = $query->num_rows;
					$query->close();
				
					if($count != 0)
					{
						// Email address is already used
					
						$this->errormsg[] = "Email is already associated to another account !";
						
						return false;					
					}
					else 
					{
						// Email address isn't already used
					
						$password = $this->hashpass($password);
						$activekey = $this->randomkey(15);				
					
						$query = $this->mysqli->prepare("INSERT INTO users (username, password, email, activekey) VALUES (?, ?, ?, ?)");
						$query->bind_param("ssss", $username, $password, $email, $activekey);
						$query->execute();
						$query->close();
						
						$message_from = "no-reply@cuonic.tk";
						$message_subj = "Account activation required !";
						$message_cont = "Hello $username<br/><br/>";
						$message_cont .= "You recently registered a new account on Cuonic Auth Test<br/>";
						$message_cont .= "To activate your account please click the following link<br/><br/>";
						$message_cont .= "<b><a href=\"http://auth.cuonic.tk/?page=activate&username=$username&key=$activekey\">Activate my account</a></b>";
						$message_head = "From: $message_from" . "\r\n";
						$message_head .= "MIME-Version: 1.0" . "\r\n";
						$message_head .= "Content-type: text/html; charset=iso-8859-1" . "\r\n";
						
						mail($email, $message_subj, $message_cont, $message_head);
					
						$this->successmsg[] = "New Account Created ! Activation email sent to your email address.";
						
						return true;					
					}
				}			
			}
			else 
			{
				return false;
			}
		}
		else 
		{
			// User is logged in
		
			$this->errormsg[] = "You are currently logged in !";
			
			return false;
		}
	}
	
	/*
	* Creates a new session for the provided username and sets cookie
	* @param string $username
	*/
	
	function newsession($username)
	{
		$hash = md5(microtime());
		
		// Fetch User ID :		
		
		$query = $this->mysqli->prepare("SELECT id FROM users WHERE username=?");
		$query->bind_param("s", $username);
		$query->bind_result($uid);
		$query->execute();
		$query->fetch();
		$query->close();
		
		// Delete all previous sessions :
		
		$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
		$query->bind_param("s", $username);
		$query->execute();
		$query->close();
		
		$ip = $_SERVER['REMOTE_ADDR'];
		$expiredate = date("Y-m-d H:i:s", strtotime("+1 month"));
		$expiretime = strtotime($expiredate);
		
		$query = $this->mysqli->prepare("INSERT INTO sessions (uid, username, hash, expiredate, ip) VALUES (?, ?, ?, ?, ?)");
		$query->bind_param("issss", $uid, $username, $hash, $expiredate, $ip);
		$query->execute();
		$query->close();
		
		setcookie("auth_session", $hash, $expiretime);
	}
	
	/*
	* Deletes the user's session based on hash
	* @param string $hash
	*/
	
	function deletesession($hash)
	{
		$query = $this->mysqli->prepare("SELECT username FROM sessions WHERE hash=?");
		$query->bind_param("s", $hash);
		$query->bind_result($username);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		$query->close();
		
		if($count == 0)
		{
			// Hash doesn't exist
		
			$this->errormsg[] = "Invalid Session Hash !";
			
			setcookie("auth_session", $hash, time() - 3600);
		}
		else 
		{
			// Hash exists, Delete all sessions for that username :
			
			$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
			$query->bind_param("s", $username);
			$query->execute();
			$query->close();
			
			setcookie("auth_session", $hash, time() - 3600);
		}
	}
	
	/*
	* Provides an associative array of user info based on session hash
	* @param string $hash
	* @return array $session
	*/
	
	function sessioninfo($hash)
	{
		$query = $this->mysqli->prepare("SELECT uid, username, expiredate, ip FROM sessions WHERE hash=?");
		$query->bind_param("s", $hash);
		$query->bind_result($session['uid'], $session['username'], $session['expiredate'], $session['ip']);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		$query->fetch();
		$query->close();
		
		if($count == 0)
		{
			// Hash doesn't exist
		
			$this->errormsg[] = "Invalid Session Hash !";
			setcookie("auth_session", $hash, time() - 3600);
			
			return false;
		}
		else 
		{
			// Hash exists
		
			return $session;			
		}
	}
	
	/* 
	* Checks if session is valid (Current IP = Stored IP + Current date < expire date)
	* @param string $hash
	* @return bool
	*/
	
	function checksession($hash)
	{
		$query = $this->mysqli->prepare("SELECT username, expiredate, ip FROM sessions WHERE hash=?");
		$query->bind_param("s", $hash);
		$query->bind_result($username, $db_expiredate, $db_ip);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		$query->fetch();
		$query->close();
		
		if($count == 0)
		{
			// Hash doesn't exist
			
			setcookie("auth_session", $hash, time() - 3600);
			
			return false;
		}
		else
		{
			if($_SERVER['REMOTE_ADDR'] != $db_ip)
			{
				// Hash exists, but IP has changed
			
				$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
				$query->bind_param("s", $username);
				$query->execute();
				$query->close();
				
				setcookie("auth_session", $hash, time() - 3600);
				
				return false;
			}
			else 
			{
				$expiredate = strtotime($db_expiredate);
				$currentdate = strtotime(date("Y-m-d H:i:s"));
				
				if($currentdate > $expiredate)
				{
					// Hash exists, IP is the same, but session has expired
				
					$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
					$query->bind_param("s", $username);
					$query->execute();
					$query->close();
					
					setcookie("auth_session", $hash, time() - 3600);
					
					return false;
				}
				else 
				{
					// Hash exists, IP is the same, date < expiry date
				
					return true;
				}
			}
		}
	}
	
	/*
	* Returns a random string, length can be modified
	* @param int $length
	* @return string $key
	*/
	
	function randomkey($length = 10)
	{
		$chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
		$key = "";
		
		for($i = 0; $i < $length; $i++)
		{
			$key .= $chars{rand(0, strlen($chars) - 1)};
		}
		
		return $key;
	}
	
	/*
	* Activate a user's account
	* @param string $username
	* @param string $key
	* @return boolean
	*/
	
	function activate($username, $key)
	{
		// Input verification
	
		if(strlen($username) == 0) { $this->errormsg[] = "Invalid URL !"; return false; }
		elseif(strlen($username) > 30) { $this->errormsg[] = "Invalid URL !"; return false; }
		elseif(strlen($username) < 3) { $this->errormsg[] = "Invalid URL !"; return false; }
		elseif(strlen($key) > 15) { $this->errormsg[] = "Invalid URL !"; return false; }
		elseif(strlen($key) < 15) { $this->errormsg[] = "Invalid URL !"; return false; }
		else
		{
			// Input is valid
			
			$query = $this->mysqli->prepare("SELECT isactive, activekey FROM users WHERE username=?");
			$query->bind_param("s", $username);
			$query->bind_result($isactive, $activekey);
			$query->execute();
			$query->store_result();
			$count = $query->num_rows;
			$query->fetch();
			$query->close();
			
			if($count == 0)
			{
				// User doesn't exist
				
				$this->errormsg[] = "Username is incorrect !";
				
				return false;
			}
			else
			{
				// User exists
				
				if($isactive == 1)
				{
					// Account is already activated
					
					$this->errormsg[] = "Account is already activated !";
					
					return true;
				}
				else
				{
					// Account isn't activated
					
					if($key == $activekey)
					{
						// Activation keys match
						
						$new_isactive = 1;
						$new_activekey = "0";
						
						$query = $this->mysqli->prepare("UPDATE users SET isactive=?, activekey=? WHERE username=?");
						$query->bind_param("iss", $new_isactive, $new_activekey, $username);
						$query->execute();
						$query->close();
						
						$this->successmsg[] = "Account successfully activated !";
						
						return true;						
					}
					else
					{
						// Activation Keys don't match
						
						$this->errormsg[] = "Activation Key is incorrect !";
						
						return false;
					}
				}
			}
		}
	}
	
	/*
	* Changes a user's password, providing the current password is known
	* @param string $username
	* @param string $currpass
	* @param string $newpass
	* @param string $verifynewpass
	* @return boolean
	*/
	
	function changepass($username, $currpass, $newpass, $verifynewpass)
	{
		
		if(strlen($username) == 0) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) > 30) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) < 3) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		if(strlen($currpass) == 0) { $this->errormsg[] = "Current Password field is empty !"; }
		elseif(strlen($currpass) < 5) { $this->errormsg[] = "Current Password is too short !"; }
		elseif(strlen($currpass) > 30) { $this->errormsg[] = "Current Password is too long !"; }
		if(strlen($newpass) == 0) { $this->errormsg[] = "New Password field is empty !"; }
		elseif(strlen($newpass) < 5) { $this->errormsg[] = "New Password is too short !"; }
		elseif(strlen($newpass) > 30) { $this->errormsg[] = "New Password is too long !"; }
		elseif(strstr($newpass, $username)) { $this->errormsg[] = "Password cannot contain the username !"; }
		elseif($newpass !== $verifynewpass) { $this->errormsg[] = "Passwords don't match !"; }
		
		if(count($this->errormsg) == 0)
		{
			$currpass = $this->hashpass($currpass);
			$newpass = $this->hashpass($newpass);
			
			$query = $this->mysqli->prepare("SELECT password FROM users WHERE username=?");
			$query->bind_param("s", $username);
			$query->bind_result($db_currpass);
			$query->execute();
			$query->store_result();
			$count = $query->num_rows;
			$query->fetch();
			$query->close();
			
			if($count == 0)
			{
				$this->errormsg[] = "Username is incorrect !";
				
				return false;
			}
			else 
			{
				if($currpass == $db_currpass)
				{
					$query = $this->mysqli->prepare("UPDATE users SET password=? WHERE username=?");
					$query->bind_param("ss", $newpass, $username);
					$query->execute();
					$query->close();
					
					$this->successmsg[] = "Password successfully changed !";
					
					return true;
				}
				else 
				{
					$this->errormsg[] = "Current Password is incorrect !";
					
					return false;
				}
			}
		}
		else 
		{
			return false;
		}
	}
	
	/*
	* Changes the stored email address based on username
	* @param string $username
	* @param string $email
	* @return boolean
	*/
	
	function changeemail($username, $email)
	{
		if(strlen($username) == 0) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) > 30) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) < 3) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		if(strlen($email) == 0) { $this->errormsg[] = "Email field is empty !"; }
		elseif(strlen($email) > 100) { $this->errormsg[] = "Email is too long !"; }
		elseif(strlen($email) < 5) { $this->errormsg[] = "Email is too short !"; }
		elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) { $this->errormsg[] = "Email address is invalid !"; }
		
		if(count($this->errormsg) == 0)
		{
			$query = $this->mysqli->prepare("SELECT email FROM users WHERE username=?");
			$query->bind_param("s", $username);
			$query->bind_result($db_email);
			$query->execute();
			$query->store_result();
			$count = $query->num_rows;
			$query->fetch();
			$query->close();
			
			if($count == 0)
			{
				$this->errormsg[] = "Username is incorrect !";
				
				return false;
			}
			else 
			{
				if($email == $db_email)
				{
					$this->errormsg[] = "New email address matches the existing one !";
					
					return false;
				}
				else 
				{
					$query = $this->mysqli->prepare("UPDATE users SET email=? WHERE username=?");
					$query->bind_param("ss", $email, $username);
					$query->execute();
					$query->close();
					
					$this->successmsg[] = "Email address successfully changed !";
					
					return true;
				}
			}
		}
		else 
		{
			return false;
		}
	}
	
	/*
	* Give the user the ability to change their password if the current password is forgotten
	* by sending email to the email address associated to that user
	* @param string $username
	* @param string $email
	* @param string $key
	* @param string $newpass
	* @param string $verifynewpass
	* @return boolean
	*/
	
	function resetpass($username = '0', $email ='0', $key = '0', $newpass = '0', $verifynewpass = '0')
	{
		$attcount = $this->getattempt($_SERVER['REMOTE_ADDR']);
			
		if($attcount >= 5)
		{
			$this->errormsg[] = "You have been temporarily locked out !";
			$this->errormsg[] = "Please wait 30 minutes.";
				
			return false;
		}
		else
		{
			if($username == '0' && $key == '0')
			{
				if(strlen($email) == 0) { $this->errormsg[] = "Email field is empty !"; }
				elseif(strlen($email) > 100) { $this->errormsg[] = "Email address is too long !"; }
				elseif(strlen($email) < 5) { $this->errormsg[] = "Email address is too short !"; }
				elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) { $this->errormsg[] = "Email address is invalid !"; }
				
				$resetkey = $this->randomkey(15);
				
				$query = $this->mysqli->prepare("SELECT username, email FROM users WHERE email=?");
				$query->bind_param("s", $email);
				$query->bind_param($username);
				$query->execute();
				$query->store_result();
				$count = $query->num_rows;
				$query->fetch();
				$query->close();
				
				if($count == 0)
				{
					$this->errormsg[] = "Email is incorrect !";
					
					$attcount = $attcount + 1;
					$remaincount = 5 - $attcount;
						
					$this->errormsg[] = "$remcount attempts remaining !";
						
					$this->addattempt($_SERVER['REMOTE_ADDR']);
						
					return false;
				}
				else
				{
					$query = $this->mysqli->prepare("UPDATE users SET resetkey=? WHERE username=?");
					$query->bind_param("ss", $resetkey, $username);
					$query->execute();
					$query->close();
					
					$message_from = "no-reply@cuonic.tk";
					$message_subj = "Password reset request !";
					$message_cont = "Hello $username<br/><br/>";
					$message_cont .= "You recently requested a password reset on Cuonic Auth Test<br/>";
					$message_cont .= "To proceed with the password reset, please click the following link :<br/><br/>";
					$message_cont .= "<b><a href=\"http://auth.cuonic.tk/?page=forgot&username=$username&key=$resetkey\">Reset My Password</a></b>";
					$message_head = "From: $message_from" . "\r\n";
					$message_head .= "MIME-Version: 1.0" . "\r\n";
					$message_head .= "Content-type: text/html; charset=iso-8859-1" . "\r\n";
						
					mail($email, $message_subj, $message_cont, $message_head);
					
					$this->successmsg[] = "Password Reset Request sent to your email address !";
						
					return true;
				}
			}
			else
			{
				// Reset Password
				
				if(strlen($key) == 0) { $this->errormsg[] = "Reset Key field is empty !"; }
				elseif(strlen($key) < 15) { $this->errormsg[] = "Reset Key is too short !"; }
				elseif(strlen($key) > 15) { $this->errormsg[] = "Reset Key is too long !"; }
				if(strlen($newpass) == 0) { $this->errormsg[] = "New Password field is empty !"; }
				elseif(strlen($newpass > 30) { $this->errormsg[] = "New Password is too long !"; }
				elseif(strlen($newpass < 5) { $this->errormsg[] = "New Password is too short !"; }
				elseif(strstr($newpass, $username)) { $this->errormsg[] = "New Password cannot contain username !"; }
				elseif($newpass !== $verifynewpass) { $this->errormsg[] = "Passwords don't match !"; }
				
				if(count($this->errormsg) == 0)
				{
					$query = $this->mysqli->prepare("SELECT resetkey FROM users WHERE username=?");
					$query->bind_param("s", $username);
					$query->bind_result($db_key);
					$query->execute();
					$query->store_result();
					$count = $query->num_rows;
					$query->fetch();
					$query->close();
					
					if($count == 0)
					{
						$this->errormsg[] = "Username is incorrect !";
						
						$attcount = $attcount + 1;
						$remaincount = 5 - $attcount;
						
						$this->errormsg[] = "$remcount attempts remaining !";
						
						$this->addattempt($_SERVER['REMOTE_ADDR']);
						
						return false;
					}
					else
					{
						if($key == $db_key)
						{
							$newpass = $this->hashpass($newpass);
							
							$resetkey = '0';
						
							$query = $this->mysqli->prepare("UPDATE users SET password=?, resetkey=? WHERE username=?");
							$query->bind_param("sss", $newpass, $resetkey, $username);
							$query->execute();
							$query->close();
							
							$this->successmsg[] = "Password successfully changed !";
							
							return true;
						}
						else
						{
							$this->errormsg[] = "Reset Key is incorrect !";
							
							$attcount = $attcount + 1;
							$remaincount = 5 - $attcount;
						
							$this->errormsg[] = "$remcount attempts remaining !";
						
							$this->addattempt($_SERVER['REMOTE_ADDR']);
						
							return false;
						}
					}
				}
				else
				{
					return false;
				}
			}
		}
	}
	
	/*
	* Deletes a user's account. Requires user's password
	* @param string $username
	* @param string $password
	* @return boolean
	*/
	
	function deleteaccount($username, $password)
	{
		if(strlen($username) == 0) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) > 30) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		elseif(strlen($username) < 3) { $this->errormsg[] = "Error encountered whilst processing your request !"; }
		if(strlen($password) == 0) { $this->errormsg[] = "Password field is empty !"; }
		elseif(strlen($password) > 30) { $this->errormsg[] = "Password is too long !"; }
		elseif(strlen($password) < 5) { $this->errormsg[] = "Password is too short !"; }
		
		if(count($this->errormsg) == 0)
		{
			$password = $this->hashpass($password);			
			
			$query = $this->mysqli->prepare("SELECT password FROM users WHERE username=?");
			$query->bind_param("s", $username);
			$query->bind_result($db_password);
			$query->execute();
			$query->store_result();
			$count = $query->num_rows;
			$query->fetch();
			$query->close();
			
			if($count == 0)
			{
				$this->errormsg[] = "Username is incorrect !";
				
				return false;
			}
			else 
			{
				if($password == $db_password)
				{
					$query = $this->mysqli->prepare("DELETE FROM users WHERE username=?");
					$query->bind_param("s", $username);
					$query->execute();
					$query->close();
					
					$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
					$query->bind_param("s", $username);
					$query->execute();
					$query->close();
					
					$this->successmsg[] = "Account deleted successfully !";
					
					return true;
				}
				else 
				{
					$this->errormsg[] = "Password is incorrect !";
					
					return false;
				}
			}
		}
		else 
		{
			return false;
		}
	}		
	
	/*
	* Adds a new attempt to database based on user's IP
	* @param string $ip
	*/
	
	function addattempt($ip)
	{
		$query = $this->mysqli->prepare("SELECT count FROM attempts WHERE ip = ?");
		$query->bind_param("s", $ip);
		$query->bind_result($attempt_count);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		$query->fetch();
		$query->close();
		
		if($count == 0)
		{
			// No record of this IP in attempts table already exists, create new
			
			$attempt_expiredate = date("Y-m-d H:i:s", strtotime("+30 minutes"));
			$attempt_count = 1;
			
			$query = $this->mysqli->prepare("INSERT INTO attempts (ip, count, expiredate) VALUES (?, ?, ?)");
			$query->bind_param("sis", $ip, $attempt_count, $attempt_expiredate);
			$query->execute();
			$query->close();
		}
		else 
		{
			// IP Already exists in attempts table, add 1 to current count
			
			$attempt_expiredate = date("Y-m-d H:i:s", strtotime("+30 minutes"));
			$attempt_count = $attempt_count + 1;
			
			$query = $this->mysqli->prepare("UPDATE attempts SET count=?, expiredate=? WHERE ip=?");
			$query->bind_param("iss", $attempt_count, $attempt_expiredate, $ip);
			$query->execute();
			$query->close();
		}
	}
	
	/*
	* Provides amount of attempts already in database based on user's IP
	* @param string $ip
	* @return int $attempt_count
	*/
	
	function getattempt($ip)
	{
		$query = $this->mysqli->prepare("SELECT count FROM attempts WHERE ip = ?");
		$query->bind_param("s", $ip);
		$query->bind_result($attempt_count);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		$query->fetch();
		$query->close();
		
		if($count == 0)
		{
			$attempt_count = 0;
		}
		
		return $attempt_count;
	}
	
	/*
	* Function used to remove expired attempt logs from database (Recommended as Cron Job)
	*/
	
	function expireattempt()
	{
		$query = $this->mysqli->prepare("SELECT ip, expiredate FROM attempts");
		$query->bind_result($ip, $expiredate);
		$query->execute();
		$query->store_result();
		$count = $query->num_rows;
		
		$curr_time = strtotime(date("Y-m-d H:i:s"));
		
		if($count != 0)
		{
			while($query->fetch())
			{
				$attempt_expiredate = strtotime($expiredate);
				
				if($attempt_expiredate <= $curr_time)
				{
					$query2 = $this->mysqli->prepare("DELETE FROM attempts WHERE ip = ?");
					$query2->bind_param("s", $ip);
					$query2->execute();
					$query2->close();
				}
			}
		}
	}

	/*
	* Hash user's password with SHA512 and base64_encode
	* @param string $password
	* @return string $password
	*/
	
	function hashpass($password)
	{
		$password = hash("SHA512", base64_encode(hash("SHA512", $password)));
		return $password;
	}
}

?>