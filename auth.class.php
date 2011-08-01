<?php

class auth
{
	public $mysqli;
	public $errormsg;
	public $successmsg;
	
	function __construct()
	{
		$this->mysqli = new mysqli("localhost", "root", "root", "auth");
	}
	
	/*
	* Log user in via MySQL Database
	* @param string username
	* @param string password
	*/
	
	function login($username, $password)
	{
		if(!isset($_COOKIE['auth_session']))
		{
			// Input verification :
		
			if(strlen($username) == 0) { $this->errormsg[] = "Username / Password is invalid !"; }
			elseif(strlen($username) > 30) { $this->errormsg[] = "Username / Password is invalid !"; }
			elseif(strlen($username) < 3) { $this->errormsg[] = "Username / Password is invalid !"; }
			elseif(strlen($password) == 0) { $this->errormsg[] = "Username / Password is invalid !"; }
			elseif(strlen($password) > 30) { $this->errormsg[] = "Username / Password is invalid !"; }
			elseif(strlen($password) < 3) { $this->errormsg[] = "Username / Password is invalid !"; }
			else 
			{
				$password = $this->hashpass($password);
			
				$query = $this->mysqli->prepare("SELECT * FROM users WHERE username=? AND password=?");
				$query->bind_param("ss", $username, $password);
				$query->execute();
				$query->store_result();
				$count = $query->num_rows;
				$query->close();
			
				if($count == 0)
				{
					$this->errormsg[] = "Username / Password is incorrect !";
				}
				else 
				{
					$this->newsession($username);				
				
					$this->successmsg[] = "You are now logged in !";
				}
			}
		}
		else 
		{
			$this->errormsg[] = "You are already logged in !";
		}
	}
	
	/*
	* Register a new user into the database
	* @param string username
	* @param string password
	* @param string verifypassword
	* @param string email
	*/
	
	function register($username, $password, $verifypassword, $email)
	{
		if(!isset($_COOKIE['auth_session']))
		{
			// Input Verification :
		
			if(strlen($username) == 0) { $this->errormsg[] = "Username field is empty !"; }
			elseif(strlen($username) > 30) { $this->errormsg[] = "Username is too long !"; }
			elseif(strlen($username) < 3) { $this->errormsg[] = "Username is too short !"; }
			if(strlen($password) == 0) { $this->errormsg[] = "Password field is empty !"; }
			elseif(strlen($password) > 30) { $this->errormsg[] = "Password is too long !"; }
			elseif(strlen($password) < 3) { $this->errormsg[] = "Password is too short !"; }
			elseif($password !== $verifypassword) { $this->errormsg[] = "Passwords don't match !"; }
			elseif(strstr($password, $username)) { $this->errormsg[] = "Password cannot contain the username !"; }
			if(strlen($email) == 0) { $this->errormsg[] = "Email field is empty !"; }
			elseif(strlen($email) > 100) { $this->errormsg[] = "Email is too long !"; }
			elseif(strlen($email) < 5) { $this->errormsg[] = "Email is too short !"; }
			elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) { $this->errormsg[] = "Email address is invalid !"; }
		
			if(count($this->errormsg) == 0)
			{
				$query = $this->mysqli->prepare("SELECT * FROM users WHERE username=?");
				$query->bind_param("s", $username);
				$query->execute();
				$query->store_result();
				$count = $query->num_rows;
				$query->close();
			
				if($count != 0)
				{
					$this->errormsg[] = "Username is already taken !";
				}
				else 
				{
					$query = $this->mysqli->prepare("SELECT * FROM users WHERE email=?");
					$query->bind_param("s", $email);
					$query->execute();
					$query->store_result();
					$count = $query->num_rows;
					$query->close();
				
					if($count != 0)
					{
						$this->errormsg[] = "Email is already associated to another account !";
					}
					else 
					{
						$password = $this->hashpass($password);					
					
						$query = $this->mysqli->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
						$query->bind_param("sss", $username, $password, $email);
						$query->execute();
						$query->close();
					
						$this->successmsg[] = "New Account Created !";
					}
				}			
			}
		}
		else 
		{
			$this->errormsg[] = "You are already logged in !";
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
			$this->errormsg[] = "Invalid Session Hash !";
		}
		else 
		{
			// Delete all sessions for that username :
			
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
			$this->errormsg[] = "Invalid Session Hash !";
		}
		else 
		{
			return $session;			
		}
	}
	
	/* Checks if session is valid (Current IP = Stored IP + Current date < expire date)
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
			$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
			$query->bind_param("s", $username);
			$query->execute();
			$query->close();
			
			setcookie("auth_session", $hash, time() - 3600);
			
			return false;
		}
		else
		{
			if($_SERVER['REMOTE_ADDR'] != $db_ip)
			{
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
					$query = $this->mysqli->prepare("DELETE FROM sessions WHERE username=?");
					$query->bind_param("s", $username);
					$query->execute();
					$query->close();
					
					setcookie("auth_session", $hash, time() - 3600);
					
					return false;
				}
				else 
				{
					return true;
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