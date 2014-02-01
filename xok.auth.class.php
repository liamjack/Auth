<?php
class auth
{   public $mysqli;
    public $errormsg;
    public $successmsg;
    public $hash;
    public $config_file = 'config.php';
    public $lang_file   = 'lang.en.php';
    
    function __construct( $language = false)
    { require_once( $this->config_file );
      if( $language )
          $this->setLang( $language );
      else
          $this->setLang( 'en' );
      $this->mysqli = new mysqli($db['host'], $db['user'], $db['pass'], $db['name']); 
      $this->db     = new PDO("mysql:host={$db['host']};dbname={$db['name']};charset=utf8", $db['user'], $db['pass']);
      unset($db['pass']); // $mysqli is public, remove password for security
    }

    /*
    * Get user hash
    * @return string $this->hash 
    */

    function getHash()
    {   return $this->hash;
    }

    /*
    * Set Language (localization)
    * @param string $loc
    * @return boolean
    */

    function setLang( $loc )
    {   unset( $this->lang );
        require( 'lang.'. $loc .'.php' );
        $this->lang = $lang; // $lang array is in the lang file...
        unset( $lang );
      return $this->loc = $loc;
    }
    
    /*
    * Log user in via MySQL Database
    * @param string $username
    * @param string $password
    * @return boolean
    */
    
    function login($username, $password)
    { 
      if(!isset($_COOKIE['auth_session']))
      {   $attcount     = $this->getattempt($_SERVER['REMOTE_ADDR']);
          if($attcount >= $this->auth_conf['max_attempts'])
          {   $this->errormsg[] = $this->lang['login_lockedout'];
              $this->errormsg[] = $this->lang['login_wait30'];
            return false;
          }
          else  // Input verification : 
          {   if(strlen($username) == 0)    
              {   $this->errormsg[] = $this->lang['login_username_empty'];
                return false;
              }
              elseif(strlen($username) > 30)
              {   $this->errormsg[] = $this->lang['login_username_long']; 
                return false;
              }
              elseif(strlen($username) < 3) 
              {   $this->errormsg[] = $this->lang['login_username_short'];
                return false;
              }
              elseif(strlen($password) == 0)
              {   $this->errormsg[] = $this->lang['login_password_empty'];
                return false;
              }
              elseif(strlen($password) > 30)
              {   $this->errormsg[] = $this->lang['login_password_short'];
                return false;
              }
              elseif(strlen($password) < 5) 
              {   $this->errormsg[] = $this->lang['login_password_long']; 
                return false;
              }
              else  // Input is valid 
              {   $password = $this->hashpass($password); 
                  list( $isactive ) = $this->db_query( 'SELECT isactive FROM users WHERE username = ? AND password = ?', array( $username, $password ), true );
                  if( !$isactive  ) // Account is not activated
                  {   $this->LogActivity($username, 'AUTH_LOGIN_FAIL', 'Account inactive');
                      $this->errormsg[] = $this->lang['login_account_inactive'];
                      return false;
                  }
                  else // Account is activated
                  {   $this->newsession($username);				
                      $this->LogActivity($username, 'AUTH_LOGIN_SUCCESS', 'User logged in');
                      $this->successmsg[] = $this->lang['login_success'];
                    return true;
                  }
              }
          }
      }
      else  // User is already logged in
      {   $this->errormsg[] = $this->lang['login_already'];
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
    {   if(!isset($_COOKIE['auth_session'])) // Input Verification : 
        {   if(strlen($username) == 0)     
                $this->errormsg[] = $this->lang['register_username_empty']; 
            elseif(strlen($username) > 30) 
                $this->errormsg[] = $this->lang['register_username_long'];  
            elseif(strlen($username) < 3)  
                $this->errormsg[] = $this->lang['register_username_short'];  

            if(strlen($password) == 0)     
                $this->errormsg[] = $this->lang['register_password_empty'];  
            elseif(strlen($password) > 30) 
                $this->errormsg[] = $this->lang['register_password_long'];  
            elseif(strlen($password) < 5)  
                $this->errormsg[] = $this->lang['register_password_short'];  
            elseif($password !== $verifypassword) 
                $this->errormsg[] = $this->lang['register_password_nomatch'];  
            elseif(strstr($password, $username))  
                $this->errormsg[] = $this->lang['register_password_username'];  

            if(strlen($email) == 0)        
                $this->errormsg[] = $this->lang['register_email_empty'];  
            elseif(strlen($email) > 100)   
                $this->errormsg[] = $this->lang['register_email_long'];  
            elseif(strlen($email) < 5)     
                $this->errormsg[] = $this->lang['register_email_short'];  
            elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) 
                $this->errormsg[] = $this->lang['register_email_invalid'];  
      
        if(count($this->errormsg) == 0) // Input is valid
        {   $user = $this->db_query( 'SELECT * FROM users WHERE username=?', array( $username ) , true );
            if(count( $user ) != 0) // Username already exists
            {   $this->LogActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', 'Username ({$username}) already exists');
                $this->errormsg[] = $this->lang['register_username_exist'];
              return false;
            }
            else  // Username is not taken
            {   $email = $this->db_query( 'SELECT * FROM users WHERE email=?', array( $email ), true );
                if( count( $email ) != 0) // Email address is already used
                {   $this->LogActivity('UNKNOWN', 'AUTH_REGISTER_FAIL', 'Email ({$email}) already exists');
                    $this->errormsg[] = $this->lang['register_email_exist'];
                  return false;					
                }
                else  // Email address isn't already used 
                {   $password  = $this->hashpass($password);
                    $activekey = $this->randomkey(15);	 

                    $this->db_query( 'INSERT INTO users (username, password, email, activekey) VALUES (?, ?, ?, ?)',  array( $username, $password, $email, $activekey ) );

                    $message_from = $this->auth_conf['email_from'];
                    $message_subj = $this->auth_conf['site_name'] . ' - Account activation required !';
                    $message_cont = 'Hello {$username}<br/><br/>';
                    $message_cont .= 'You recently registered a new account on ' . $this->auth_conf['site_name'] . '<br/>';
                    $message_cont .= 'To activate your account please click the following link<br/><br/>';
                    $message_cont .= '<b><a href=\'' . $this->auth_conf['base_url'] . '?page=activate&username={$username}&key={$activekey}\'>Activate my account</a></b>';
                    $message_head = 'From: {$message_from}' . '\r\n';
                    $message_head .= 'MIME-Version: 1.0' . '\r\n';
                    $message_head .= 'Content-type: text/html; charset=iso-8859-1' . '\r\n';
                    
                    mail($email, $message_subj, $message_cont, $message_head);
                    $this->LogActivity($username, 'AUTH_REGISTER_SUCCESS', 'Account created and activation email sent');
                    $this->successmsg[] = $this->lang['register_success'];
                  return true;					
                }
            }			
        }
        else 
          return false;
      }
      else  // User is logged in 
      {   $this->errormsg[] = $this->lang['register_email_loggedin'];
        return false;
      }
    }
    
    /*
    * Creates a new session for the provided username and sets cookie
    * @param string $username
    */
    
    function newsession($username)
    {   $hash        = md5(microtime());
        $ip          = $_SERVER['REMOTE_ADDR'];
        $expiredate  = date('Y-m-d H:i:s', strtotime($this->auth_conf['session_duration']));
        $expiretime  = strtotime($expiredate);
        list( $uid ) = $this->db_query( 'SELECT id FROM users WHERE username=?', array( $username ), true );
        $this->db_query( 'DELETE FROM sessions WHERE username=?', array( $username ) );
        $this->db_query( 'INSERT INTO sessions (uid, username, hash, expiredate, ip) VALUES (?, ?, ?, ?, ?)', array( $uid, $username, $hash, $expiredate, $ip ) );
        setcookie('auth_session', $hash, $expiretime);
    }
    
    /*
    * Deletes the user's session based on hash
    * @param string $hash
    */
    
    function deletesession($hash)
    {   list( $username ) = $this->db_query ( 'SELECT username FROM sessions WHERE hash=?', array( $hash ), true );
        if( !$username ) // Hash doesnt exist 
        {   $this->LogActivity('UNKNOWN', 'AUTH_LOGOUT', 'User session cookie deleted - Database session not deleted - Hash ({'. $hash .'}) didnt exist');
            $this->errormsg[] = $this->lang['deletesession_invalid'];
            setcookie('auth_session', $hash, time() - 3600);
        }
        else  // Hash exists, Delete all sessions for that username : 
        {   $this->db_query( 'DELETE FROM sessions WHERE username=?', array( $username ) );
            $this->LogActivity($username, 'AUTH_LOGOUT', 'User session cookie deleted - Database session deleted - Hash ({$hash})');
            setcookie('auth_session', $hash, time() - 3600);
        }
    }
    
    /*
    * Provides an associative array of user info based on session hash
    * @param string $hash
    * @return array $session
    */
    
    function sessioninfo($hash)
    {   list( $session['uid'], $session['username'], $session['expiredate'], $session['ip'] ) = $this->db_query( 'SELECT uid, username, expiredate, ip FROM sessions WHERE hash=?', array( $hash ), true );
        if( !$session['uid'] ) // Hash doesnt exist 
        {   $this->errormsg[] = $this->lang['sessioninfo_invalid']; 
            setcookie('auth_session', $hash, time() - 3600); 
          return false;
        }
        else // Hash exists
          return $session;			
    }
    
    /* 
    * Checks if session is valid (Current IP = Stored IP + Current date < expire date)
    * @param string $hash
    * @return bool
    */
    
    function checksession($hash)
    {   list( $username, $db_expiredate, $db_ip ) = $this->db_query( 'SELECT username, expiredate, ip FROM sessions WHERE hash=?', array( $hash ), true );
        if( !$username ) // Hash doesnt exist 
        {   setcookie('auth_session', $hash, time() - 3600); 
            $this->LogActivity($username, 'AUTH_CHECKSESSION', 'User session cookie deleted - Hash ({'. $hash .'}) didnt exist');
          return false;
        }
        else
        {   if($_SERVER['REMOTE_ADDR'] != $db_ip) // Hash exists, but IP has changed 
            {   $this->db_query( 'DELETE FROM sessions WHERE username=?', array( $username ) );
                setcookie('auth_session', $hash, time() - 3600); 
                $this->LogActivity($username, 'AUTH_CHECKSESSION', 'User session cookie deleted - IP Different ( DB : {$db_ip} / Current : ' . $_SERVER['REMOTE_ADDR'] . ' )');
              return false;
            }
            else 
            {   $expiredate  = strtotime($db_expiredate);
                $currentdate = strtotime(date('Y-m-d H:i:s'));
                if($currentdate > $expiredate) // Hash exists, IP is the same, but session has expired 
                {   $this->db_query( 'DELETE FROM sessions WHERE username=?', array( $username ) );
                    setcookie('auth_session', $hash, time() - 3600);
                    $this->LogActivity($username, 'AUTH_CHECKSESSION', 'User session cookie deleted - Session expired ( Expire date : {$db_expiredate} )');
                  return false;
                }
                else // Hash exists, IP is the same, date < expiry date
                  return true;
            }
        }
    }
    
    /*
    * Returns a random string, length can be modified
    * @param int $length
    * @return string $key
    */
    
    function randomkey($length = 10)
    {   $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
        $key = '';
        for($i = 0; $i < $length; $i++)
            $key .= $chars{rand(0, strlen($chars) - 1)};
      return $key;
    }
    
    /*
    * Activate a user's account
    * @param string $username
    * @param string $key
    * @return boolean
    */
    
    function activate($username, $key)
    { // Input verification 
      if(strlen($username) == 0)
      {   $this->errormsg[] = $this->lang['activate_username_empty'];
        return false;
      }
      elseif(strlen($username) > 30)
      {   $this->errormsg[] = $this->lang['activate_username_long']; 
        return false;
      }
      elseif(strlen($username) < 3)
      {   $this->errormsg[] = $this->lang['activate_username_short'];
        return false;
      }
      elseif(strlen($key) == 0)
      {   $this->errormsg[] = $this->lang['activate_key_empty'];     
        return false;
      }
      elseif(strlen($key) > 15)
      {   $this->errormsg[] = $this->lang['activate_key_long'];
        return false;
      }
      elseif(strlen($key) < 15)
      {   $this->errormsg[] = $this->lang['activate_key_short'];     
        return false;
      }
      else
      {   list( $isactive, $activekey ) = $this->db_query( 'SELECT isactive, activekey FROM users WHERE username=?', array( $username ), true );
        
        if( !$activekey ) // User doesnt exist 
        {   $this->LogActivity('UNKNOWN', 'AUTH_ACTIVATE_FAIL', 'Username Incorrect : {$username}');				
            $this->errormsg[] = $this->lang['activate_username_incorrect']; 
          return false;
        }
        else // User exists 
        { if($isactive == 1) // Account is already activated 
          {   $this->LogActivity($username, 'AUTH_ACTIVATE_FAIL', 'Account already activated');					
              $this->errormsg[] = $this->lang['activate_account_activated']; 
            return true;
          }
          else // Account isn't activated 
          { if($key == $activekey) // Activation keys match 
            {   $new_isactive  = 1;
                $new_activekey = '0'; 
                $this->db_query( 'UPDATE users SET isactive=?, activekey=? WHERE username=?', array( $new_isactive, $new_activekey, $username ) );
                $this->LogActivity($username, 'AUTH_ACTIVATE_SUCCESS', 'Activation successful. Key Entry deleted.');			
                $this->successmsg[] = $this->lang['activate_success'];
              return true;						
            }
            else // Activation Keys dont match 
            {   $this->LogActivity($username, 'AUTH_ACTIVATE_FAIL', 'Activation keys dont match ( DB : {'. $activekey .'} / Given : {$key} )');						
                $this->errormsg[] = $this->lang['activate_key_incorrect']; 
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
    {   if(strlen($username) == 0)
            $this->errormsg[] = $this->lang['changepass_username_empty'];  
        elseif(strlen($username) > 30)
            $this->errormsg[] = $this->lang['changepass_username_long'];  
        elseif(strlen($username) < 3)
            $this->errormsg[] = $this->lang['changepass_username_short'];
  /************************************************************************/
        if(strlen($currpass) == 0)
            $this->errormsg[] = $this->lang['changepass_currpass_empty'];
        elseif(strlen($currpass) < 5)
            $this->errormsg[] = $this->lang['changepass_currpass_short'];
        elseif(strlen($currpass) > 30)
            $this->errormsg[] = $this->lang['changepass_currpass_long']; 
  /************************************************************************/
        if(strlen($newpass) == 0)
            $this->errormsg[] = $this->lang['changepass_newpass_empty']; 
        elseif(strlen($newpass) < 5)
            $this->errormsg[] = $this->lang['changepass_newpass_short']; 
        elseif(strlen($newpass) > 30)
            $this->errormsg[] = $this->lang['changepass_newpass_long']; 
        elseif(strstr($newpass, $username))
            $this->errormsg[] = $this->lang['changepass_password_username']; 
        elseif($newpass !== $verifynewpass)
            $this->errormsg[] = $this->lang['changepass_password_nomatch'];  
      
      if(count($this->errormsg) == 0)
      {   $currpass    = $this->hashpass($currpass);
          $newpass     = $this->hashpass($newpass);
          list( $db_currpass ) = $this->db_query( 'SELECT password FROM users WHERE username=?', array( $username ), true );
          
          if( !$db_currpass )
          {   $this->LogActivity('UNKNOWN', 'AUTH_CHANGEPASS_FAIL', 'Username Incorrect ({$username})');				
              $this->errormsg[] = $this->lang['changepass_username_incorrect'];
              return false;
          }
          else 
          {   if($currpass == $db_currpass)
              {   $this->db_query( 'UPDATE users SET password=? WHERE username=?', array( $newpass, $username ) );
                  $this->LogActivity($username, 'AUTH_CHANGEPASS_SUCCESS', 'Password changed');					
                  $this->successmsg[] = $this->lang['changepass_success'];
                return true;
              }
              else 
              {   $this->LogActivity($username, 'AUTH_CHANGEPASS_FAIL', 'Current Password Incorrect ( DB : {$db_currpass} / Given : {$currpass} )');					
                  $this->errormsg[] = $this->lang['changepass_currpass_incorrect']; 
                return false;
              }
          }
        }
        else 
          return false;
    }
    
    /*
    * Changes the stored email address based on username
    * @param string $username
    * @param string $email
    * @return boolean
    */
    
    function changeemail($username, $email)
    {   if(strlen($username) == 0)    
            $this->errormsg[] = $this->lang['changeemail_username_empty'];  
        elseif(strlen($username) > 30)
            $this->errormsg[] = $this->lang['changeemail_username_long'];  
        elseif(strlen($username) < 3) 
            $this->errormsg[] = $this->lang['changeemail_username_short'];  
  /*****************************************************************************/
        if(strlen($email) == 0)       
            $this->errormsg[] = $this->lang['changeemail_email_empty'];  
        elseif(strlen($email) > 100)  
            $this->errormsg[] = $this->lang['changeemail_email_long'];  
        elseif(strlen($email) < 5)   
            $this->errormsg[] = $this->lang['changeemail_email_short'];  
        elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) 
            $this->errormsg[] = $this->lang['changeemail_email_invalid'];  
      
      if(count($this->errormsg) == 0)
      {   list( $db_email ) = $this->db_query( 'SELECT email FROM users WHERE username=?', array( $username ), true );
        
          if( !$db_email )
          {   $this->LogActivity('UNKNOWN', 'AUTH_CHANGEEMAIL_FAIL', 'Username Incorrect ({$username})');				
              $this->errormsg[] = $this->lang['changeemail_username_incorrect'];
            return false;
          }
          else 
          {   if($email == $db_email)
              {   $this->LogActivity($username, 'AUTH_CHANGEEMAIL_FAIL', 'Old and new email matched ({$email})');			   
                  $this->errormsg[] = $this->lang['changeemail_email_match']; 
                return false;
              }
              else 
              {   $this->db_query( 'UPDATE users SET email=? WHERE username=?', array( $email, $username ) );
                  $this->LogActivity($username, 'AUTH_CHANGEEMAIL_SUCCESS', 'Email changed from {$db_email} to {$email}');		
                  $this->successmsg[] = $this->lang['changeemail_success'];
                return true;
              }
          }
      }
      else 
        return false;
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
    {   $attcount = $this->getattempt($_SERVER['REMOTE_ADDR']); 
        if($attcount >= $this->auth_conf['max_attempts'])
        {   $this->errormsg[] = $this->lang['resetpass_this->lockedout'];
            $this->errormsg[] = $this->lang['resetpass_wait30'];
          return false;
        }
      else
      {   if($username == '0' && $key == '0')
          {   if(strlen($email) == 0) 
                  $this->errormsg[] = $this->lang['resetpass_email_empty'];  
              elseif(strlen($email) > 100) 
                  $this->errormsg[] = $this->lang['resetpass_email_long'];  
              elseif(strlen($email) < 5) 
                  $this->errormsg[] = $this->lang['resetpass_email_short'];  
              elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) 
                  $this->errormsg[] = $this->lang['resetpass_email_invalid'];  
            
            $resetkey = $this->randomkey(15);
            list( $username ) = $this->db_query( 'SELECT username FROM users WHERE email=?', array( $email ), true );
            
            if( !$username )
            {   $this->errormsg[] = $this->lang['resetpass_email_incorrect'];
                $attcount         = $attcount + 1;
                $remaincount      = $this->auth_conf['max_attempts'] - $attcount;
                $this->LogActivity('UNKNOWN', 'AUTH_RESETPASS_FAIL', 'Email incorrect ({$email})');
                $this->errormsg[] = sprintf($this->lang['resetpass_attempts_remaining'], $remaincount);
                $this->addattempt($_SERVER['REMOTE_ADDR']);
              return false;
            }
            else
            {   $this->db_query( 'UPDATE users SET resetkey=? WHERE username=?', array( $resetkey, $username ) );
              
                $message_from = $this->auth_conf['email_from'];
                $message_subj = $this->auth_conf['site_name'] . ' - Password reset request !';
                $message_cont = 'Hello {$username}<br/><br/>';
                $message_cont .= 'You recently requested a password reset on ' . $this->auth_conf['site_name'] . '<br/>';
                $message_cont .= 'To proceed with the password reset, please click the following link :<br/><br/>';
                $message_cont .= '<b><a href=\'' . $this->auth_conf['base_url'] . '?page=forgot&username={$username}&key={$resetkey}\'>Reset My Password</a></b>';
                $message_head = 'From: {$message_from}' . '\r\n';
                $message_head .= 'MIME-Version: 1.0' . '\r\n';
                $message_head .= 'Content-type: text/html; charset=iso-8859-1' . '\r\n';
              mail($email, $message_subj, $message_cont, $message_head);
                $this->LogActivity($username, 'AUTH_RESETPASS_SUCCESS', 'Reset pass request sent to {$email} ( Key : {$resetkey} )');
                $this->successmsg[] = $this->lang['resetpass_email_sent'];
              return true;
            }
          }
        else // Reset Password
        {   if(strlen($key) == 0) 
                $this->errormsg[] = $this->lang['resetpass_key_empty'];  
            elseif(strlen($key) < 15) 
                $this->errormsg[] = $this->lang['resetpass_key_short'];  
            elseif(strlen($key) > 15) 
                $this->errormsg[] = $this->lang['resetpass_key_long'];  

            if(strlen($newpass) == 0) 
                $this->errormsg[] = $this->lang['resetpass_newpass_empty'];  
            elseif(strlen($newpass) > 30) 
                $this->errormsg[] = $this->lang['resetpass_newpass_long'];  
            elseif(strlen($newpass) < 5) 
                $this->errormsg[] = $this->lang['resetpass_newpass_short'];  
            elseif(strstr($newpass, $username)) 
                $this->errormsg[] = $this->lang['resetpass_newpass_username'];  
            elseif($newpass !== $verifynewpass) 
                $this->errormsg[] = $this->lang['resetpass_newpass_nomatch'];  
          
          if(count($this->errormsg) == 0)
          {   list( $db_key ) = $this->db_query( 'SELECT resetkey FROM users WHERE username=?', array( $username ), true );
              if( !$db_key )
              {   $this->errormsg[] = $this->lang['resetpass_username_incorrect'];
                  $attcount         = $attcount + 1;
                  $remaincount      = $this->auth_conf['max_attempts'] - $attcount;
                  $this->LogActivity('UNKNOWN', 'AUTH_RESETPASS_FAIL', 'Username incorrect ({$username})');				
                  $this->errormsg[] = sprintf($this->lang['resetpass_attempts_remaining'], $remaincount);
                  $this->addattempt($_SERVER['REMOTE_ADDR']);
                return false;
              }
              else
              {   if($key == $db_key)
                  {   $newpass  = $this->hashpass($newpass);
                      $resetkey = '0';
                      $this->db_query( 'UPDATE users SET password=?, resetkey=? WHERE username=?', array( $newpass, $resetkey, $username ) );;
                      $this->LogActivity($username, 'AUTH_RESETPASS_SUCCESS', 'Password reset - Key reset');				
                      $this->successmsg[] = $this->lang['resetpass_success'];
                    return true;
                  }
                  else
                  {
                      $this->errormsg[] = $this->lang['resetpass_key_incorrect'];
                      $attcount = $attcount + 1;
                      $remaincount = 5 - $attcount;
                      $this->LogActivity($username, 'AUTH_RESETPASS_FAIL', 'Key Incorrect ( DB : {$db_key} / Given : {$key} )');	
                      $this->errormsg[] = sprintf($this->lang['resetpass_attempts_remaining'], $remaincount);
                      $this->addattempt($_SERVER['REMOTE_ADDR']);
                    return false;
                  }
              }
          }
          else
            return false;
        }
      }
    }
    
    /*
    * Checks if the reset key is correct for provided username
    * @param string $username
    * @param string $key
    * @return boolean
    */
    
    function checkresetkey($username, $key)
    {   $attcount = $this->getattempt($_SERVER['REMOTE_ADDR']);
        
        if($attcount >= $this->auth_conf['max_attempts'])
        {   $this->errormsg[] = $this->lang['resetpass_this->lockedout'];
            $this->errormsg[] = $this->lang['resetpass_wait30'];
          return false;
        }
      else
      {   if(strlen($username) == 0) 
              return false;  
          elseif(strlen($username) > 30) 
              return false;  
          elseif(strlen($username) < 3) 
              return false;  
          elseif(strlen($key) == 0) 
              return false;  
          elseif(strlen($key) < 15) 
              return false;  
          elseif(strlen($key) > 15) 
              return false;  
          else
          {   list( $db_key ) = $this->db_query( 'SELECT resetkey FROM users WHERE username=?', array( $username ), true );
              if( !$db_key )
              {   $this->LogActivity('UNKNOWN', 'AUTH_CHECKRESETKEY_FAIL', 'Username doesnt exist ({$username})');
                  $this->addattempt($_SERVER['REMOTE_ADDR']);
                  $this->errormsg[] = $this->lang['checkresetkey_username_incorrect'];
                  $attcount = $attcount + 1;
                  $remaincount = $this->auth_conf['max_attempts'] - $attcount;
                  $this->errormsg[] = sprintf($this->lang['checkresetkey_attempts_remaining'], $remaincount);
                return false;
              }
              else
              {   if($key == $db_key)
                      return true;
                  else
                  {   $this->LogActivity($username, 'AUTH_CHECKRESETKEY_FAIL', 'Key provided is different to DB key ( DB : {$db_key} / Given : {$key} )');
                      $this->addattempt($_SERVER['REMOTE_ADDR']);
                      $this->errormsg[] = $this->lang['checkresetkey_key_incorrect'];
                      $attcount = $attcount + 1;
                      $remaincount = $this->auth_conf['max_attempts'] - $attcount;
                      $this->errormsg[] = sprintf($this->lang['checkresetkey_attempts_remaining'], $remaincount);
                    return false;
                  }
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
    {   if(strlen($username) == 0)      
            $this->errormsg[] = $this->lang['deleteaccount_username_empty'];  
        elseif(strlen($username) > 30)  
            $this->errormsg[] = $this->lang['deleteaccount_username_long'];  
        elseif(strlen($username) < 3)   
            $this->errormsg[] = $this->lang['deleteaccount_username_short']; 

        if(strlen($password) == 0)      
            $this->errormsg[] = $this->lang['deleteaccount_password_empty'];
        elseif(strlen($password) > 30)  
            $this->errormsg[] = $this->lang['deleteaccount_password_long'];
        elseif(strlen($password) < 5)   
            $this->errormsg[] = $this->lang['deleteaccount_password_short']; 
      
      if(count($this->errormsg) == 0)
      {   $password    = $this->hashpass($password);			
          list( $db_password ) = $this->db_query( 'SELECT password FROM users WHERE username=?', array( $username ), true );
          if( !$db_password )
          {   $this->LogActivity('UNKNOWN', 'AUTH_DELETEACCOUNT_FAIL', 'Username Incorrect ({$username})');				
              $this->errormsg[] = $this->lang['deleteaccount_username_incorrect'];
            return false;
          }
          else 
          {   if( $password == $db_password[0] )
              {   $this->db_query( 'DELETE FROM users WHERE username=?',    array( $username ) );
                  $this->db_query( 'DELETE FROM sessions WHERE username=?', array( $username ) );
                  $this->LogActivity($username, 'AUTH_DELETEACCOUNT_SUCCESS', 'Account deleted - Sessions deleted');			
                  $this->successmsg[] = $this->lang['deleteaccount_success'];
                return true;
              }
              else 
              {   $this->LogActivity($username, 'AUTH_DELETEACCOUNT_FAIL', 'Password incorrect ( DB : {$db_password} / Given : {$password} )');					
                  $this->errormsg[] = $this->lang['deleteaccount_password_incorrect'];
                return false;
              }
          }
      }
      else 
        return false;
    }
    
    /*
    * Adds a new attempt to database based on user's IP
    * @param string $ip
    */
    
    function addattempt($ip)
    {   $attempt_count = $this->db_query( 'SELECT count FROM attempts WHERE ip = ?', array( $ip ), true );
        if($count == 0) // No record of this IP in attempts table already exists, create new
        {   $attempt_expiredate = date('Y-m-d H:i:s', strtotime($this->auth_conf['security_duration']));
            $attempt_count = 1;
            $this->db_query( 'INSERT INTO attempts (ip, count, expiredate) VALUES (?, ?, ?)', array( $ip, $attempt_count, $attempt_expiredate ) );
        }
        else  // IP Already exists in attempts table, add 1 to current count 
        {   $attempt_expiredate = date('Y-m-d H:i:s', strtotime($this->auth_conf['security_duration']));
            $attempt_count = $attempt_count + 1; 
            $this->db_query( 'UPDATE attempts SET count=?, expiredate=? WHERE ip=?', array( $attempt_count, $attempt_expiredate, $ip ) );
        }
    }
    
    /*
    * Provides amount of attempts already in database based on user's IP
    * @param string $ip
    * @return int $attempt_count
    */
    
    function getattempt($ip)
    {   list( $attempt_count ) = $this->db_query( 'SELECT count FROM attempts WHERE ip = ?', array( $ip ), true );
      return $attempt_count;
    }
    
    /*
    * Function used to remove expired attempt logs from database (Recommended as Cron Job)
    */
    
    function expireattempt()
    {   list( $ip, $expiredate ) = $this->db_query( 'SELECT ip, expiredate FROM attempts', array( ), true );
        $curr_time = strtotime(date('Y-m-d H:i:s'));
        if( !$expiredate )
        {   while($query->fetch()) // TODO: CHECK THIS OUT, WE NEED TO LOOP THROUGH A VALID VARIABLE!!!
            {   $attempt_expiredate = strtotime($expiredate);
                if($attempt_expiredate <= $curr_time)
                    $this->db_query( 'DELETE FROM attempts WHERE ip = ?', array( $ip ) );
            }
        }
    }
    
    /*
    * Logs users actions on the site to database for future viewing
    * @param string $username
    * @param string $action
    * @param string $additionalinfo
    * @return boolean
    */
    
    function LogActivity($username, $action, $additionalinfo = 'none')
    {   if( !$username )
            $username = 'GUEST';
        elseif(strlen($username) < 3)
        {   $this->errormsg[] = $this->lang['logactivity_username_short'];
          return false;
        }
        elseif(strlen($username) > 30)
        {   $this->errormsg[] = $this->lang['logactivity_username_long'];
          return false;
        }
        
        if(strlen($action) == 0)
        {   $this->errormsg[] = $this->lang['logactivity_action_empty'];
          return false;
        }
        elseif(strlen($action) < 3)
        {   $this->errormsg[] = $this->lang['logactivity_action_short'];
          return false;
        }
        elseif(strlen($action) > 100)
        {   $this->errormsg[] = $this->lang['logactivity_action_long'];
          return false;
        }
        
        if(count($this->errormsg) == 0)
        {   $ip = $_SERVER['REMOTE_ADDR'];
            $date = date('Y-m-d H:i:s');
            $this->db_query( 'INSERT INTO activitylog (date, username, action, additionalinfo, ip) VALUES (?, ?, ?, ?, ?)', array( $date, $username, $action, $additionalinfo, $ip ) );
          return true;
        }
    }

    /*
    * Hash user's password with SHA512, base64_encode, ROT13 and salts !
    * @param string $password
    * @return string $hashed_pass
    */
    
    function hashpass($password)
    {   $hashed_pass = hash('SHA512', base64_encode( str_rot13( hash('SHA512', str_rot13( $this->auth_conf['salt_1'] . $password . $this->auth_conf['salt_2'])))));
        $this->hash = $hashed_pass;
      return $hashed_pass;
    }

    /*
    * Query Database and send an SQL
    * @param string $query
    * @param array $params
    * @param bool $fetch
    * @return array fetched values
    */

    function db_query( $query, $params, $fetch = false )
    {   $thing = $this->db->prepare( $query );
        if( !is_array( $params ) )
        {   $tmp = $params;
            unset( $params );
            $params = array( $tmp );
        }
        $thing->execute( $params );
        if( $fetch )
            return $thing->fetch();
      return true;
    }
}
