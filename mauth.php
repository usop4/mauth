<?php

/**
 * Auth library compatible with PEAR::Auth
 * using salt hash and modern crypt.
 *
 * PHP versions 5.2 or later
 *
 * LICENSE: This source file si subject to version 3.0 of the PHP license
 * that is available throu the world-wide-web at the following URI:
 * http://www.php.net/license/3_0.txt
 *
 * @category    Authentication
 * @package     Auth
 * @author      t.uehara
 * @copyright   2013 The PHP Group
 */

class Auth {

    var $expire = 0;
    var $expired = false;
    var $idle = 0;
    var $idled = false;

    var $username = '';
    var $password = '';
    var $_postUsername = 'username';
    var $_postPassword = 'password';

    var $server;
    var $post;
    var $cookie;
    var $authdata;
    var $authChecks = 0;

    var $loginFunction = '';
    var $checkAuthCallback = '';
    var $loginCallback = '';
    var $loginFailedCallback = '';
    var $logoutCallback = '';

    var $_sessionName = '_authsession';


    /**
     *  Constructor
     *
     * @param $storageDriver
     * @param $options
     * @param $loginFunction
     * @return \Auth
     */
    function __construct($storageDriver,$options,$loginFunction){

        $this->options =& $options;

        session_set_cookie_params(60*60,$httponly=true);
        session_start();

        $this->session =& $_SESSION[$this->_sessionName];
        $this->server =& $_SERVER;
        $this->post =& $_POST;
        $this->cookie =& $_COOKIE;

        $this->loginFunction = $loginFunction;

        if (!empty($this->options['postUsername'])) {
            $this->_postUsername = $this->options['postUsername'];
            unset($this->options['postUsername']);
        }
        if (!empty($this->options['postPassword'])) {
            $this->_postPassword = $this->options['postPassword'];
            unset($this->options['postPassword']);
        }
    }

    /**
     * @access private
     * @return PDO|string
     */
    function setPDO(){
        $dsn = parse_url($this->options["dsn"]);
        //print_r($dsn);
        if("mysqli"== $dsn["scheme"]){
            $pdo = new PDO(
                'mysql:host='.$dsn["host"].';dbname='.str_replace("/","",$dsn["path"]),
                $dsn["user"],
                $dsn["pass"]);
            $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);
            return $pdo;
        }
        elseif("sqlite"==$dsn["scheme"]){
            $pdo = new PDO($this->options["dsn"]);
            return $pdo;
        }
        else{
            return false;
        }
    }

    /**
     * @access private
     * @return PDO|string
     */
    function setSaltPDO(){
        $dsn = parse_url($this->options["saltdsn"]);
        if("mysqli"== $dsn["scheme"]){
            $pdo = new PDO(
                'mysql:host='.$dsn["host"].';dbname='.str_replace("/","",$dsn["path"]),
                $dsn["user"],
                $dsn["pass"]);
            $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);
            return $pdo;
        }
        elseif("sqlite"==$dsn["scheme"]){
            $pdo = new PDO($this->options["saltdsn"]);
            return $pdo;
        }
        else{
            return false;
        }
    }

    /**
     * @access public
     * @return bool
     */
    public function checkAuth(){
        if( $this->expire > 0 ){
            $this->expired = true;
            $this->logout();
            return false;
        }

        if( $this->idle > 0 ){
            $this->idled = true;
            $this->logout();
            return false;
        }

        if( isset($this->session['registered'])){
            if (is_callable($this->checkAuthCallback)) {

                $checkCallback = call_user_func_array($this->checkAuthCallback, [$this->username, &$this]);
                if ($checkCallback == false) {
                    $this->expired = true;
                    $this->logout();
                    return false;
                }
            }
            return true;
        }
        return false;

    }


    /**
     * @access public
     * @param string Username
     * @param string Password
     * @return mixed
     */
    function addUser($username,$password){

        $salt = mcrypt_create_iv(22,MCRYPT_DEV_URANDOM);
        $hash = crypt($password,$salt);

        $pdo = $this->setPDO();
        try{
            $sql = sprintf('INSERT INTO %s (%s,%s) VALUES (?,?)',
                $this->options["table"],
                $this->options["usernamecol"],
                $this->options["passwordcol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$username,$hash]);
        }
        catch (PDOException $Exception ){
            echo $Exception->getMessage();
        }

        $pdo = $this->setSaltPDO();
        try{
            if($this->options["table"]!=$this->options["salttable"]){
                $sql = sprintf('INSERT INTO %s (%s,%s) VALUES (?,?)',
                    $this->options["salttable"],
                    $this->options["usernamecol"],
                    $this->options["saltcol"]);
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$username,$salt]);
            }
            else{
                $sql = sprintf('UPDATE %s SET %s=? WHERE %s=?',
                    $this->options["salttable"],
                    $this->options["saltcol"],
                    $this->options["usernamecol"]);
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$salt,$username]);
            }
        }
        catch (PDOException $Exception ){
            echo $Exception->getMessage();
        }
        return true;
    }

    /**
     * @access public
     * @param string Username
     * @param string Password
     * @return mixed
     */
    function changePassword($username,$password){

        $salt = mcrypt_create_iv(22,MCRYPT_DEV_URANDOM);
        $hash = crypt($password,$salt);

        $pdo = $this->setPDO();
        if(!empty($pdo)){
            $sql = sprintf('UPDATE %s SET %s=? WHERE %s=?',
                $this->options["table"],
                $this->options["passwordcol"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$hash,$username]);
        }

        $pdo = $this->setSaltPDO();
        if(!empty($pdo)){
            $sql = sprintf('UPDATE %s SET %s=? WHERE %s=?',
                $this->options["salttable"],
                $this->options["saltcol"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$salt,$username]);
        }

    }


    /**
     * @access public
     * @param string Username
     * @return mixed
     */
    function removeUser($username){

        $pdo = $this->setPDO();
        if(!empty($pdo)){
            $sql = sprintf('DELETE FROM %s WHERE %s=?',
                $this->options["table"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$username]);
        }

        $pdo = $this->setSaltPDO();
        if(!empty($pdo)){
            $sql = sprintf('DELETE FROM %s WHERE %s=?',
                $this->options["salttable"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$username]);
        }
    }


    /**
     * @access public
     * @return void
     */
    public function logout(){

        if(is_callable($this->logoutCallback)){
            call_user_func_array($this->logoutCallback,[$this->session['username'],&$this]);
        }

        $this->username = '';
        $this->password = '';
        $this->session = null;
    }

    /**
     * @access public
     * @return bool
     */
    function getAuth(){
        return $this->checkAuth();
    }

    /**
     * @param string Name
     * @return mixed
     * @access public
     */
    public function getAuthData($name = null){

        if(!isset($this->session['data'])){
            return null;
        }
        if(!isset($name)){
            return $this->session['data'];
        }
        if(isset($name) && isset($this->session['data'][$name])){
            return $this->session['data'][$name];
        }
        return null;
    }

    /**
     * @return string
     * @access public
     */
    public function getUsername(){
        if(isset($this->session["username"])){
            return $this->session["username"];
        }
        return('');
    }

    /**
     * @access public
     * @return array
     */
    function listUsers(){
        $users = [];
        $pdo = $this->setPDO();
        $sql = sprintf("SELECT %s FROM %s",
            $this->options["usernamecol"],
            $this->options["table"]);
        try{
            $stmt = $pdo->prepare($sql);
            $stmt->execute();
            while( $user = $stmt->fetch(PDO::FETCH_NUM)){
                array_push($users,$user[0]);
            }
        }
        catch (PDOException $Exception ){
            echo $Exception->getMessage();
        }
        return $users;
    }

    /**
     * @param string Username
     * @return void
     * @access public
     */
    public function setAuth($username){
        session_regenerate_id(true);
        $this->session = [];
        $this->session['data'] = [];
        $this->session['sessionip'] = $this->server['REMOTE_ADDR'];
        $this->session['sessionuseragent'] = $this->server['HTTP_USER_AGENT'];
        if(isset($this->server['HTTP_X_FORWAREDER_FOR'])){
            $this->session['sessionforwardedfor'] = $this->server['HTTP_X_FORWAREDER_FOR'];
        }
        if(empty($this->session['challengekey'])){
            $this->session['challengekey'] = md5($username.microtime());
        }
        $this->session['challengecookie'] = md5($this->session['challengekey'].microtime());
        setcookie('authchallenge',$this->session['challengecookie'],0,'/');

        $this->session['registered'] = true;
        $this->session['username'] = $username;
        $this->session['timestamp'] = time();
        $this->session['idle'] = time();

    }

    /**
     * @param string Name of the data field
     * @param mixed Value of the data field
     * @param boolean
     * @return void
     * @access public
     */
    public function setAuthData($name,$value,$overwrite = true){
        echo "setAuthData is not supported";
    }

    /**
     *
     */
    public function sessionValidThru(){
        if(!isset($this->session['idle'])){
            return 0;
        }
        if($this->idle == 0){
            return 0;
        }
        return ($this->session['idle'] + $this->idle);
    }

    /**
     * Start new auth session
     *
     * @return void
     * @access public
     */
    public function start(){
        session_regenerate_id(true);

        if( isset($this->post[$this->_postUsername])){
            $this->username = $this->post[$this->_postUsername];
        }
        if( isset($this->post[$this->_postPassword])){
            $this->password = $this->post[$this->_postPassword];
        }

        if(!$this->checkAuth()){
            $this->login();
        }
    }

    /**
     * Login function
     *
     * @return void
     * @access private
     */
    function login()
    {

        $login_ok = false;

        if(isset($_POST["username"])){

            $passwordcol = $this->options["passwordcol"];
            $saltcol = $this->options["saltcol"];

            $pdo = $this->setPDO();
            $sql = sprintf('SELECT * FROM %s WHERE %s=?;',
                $this->options["table"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$this->post['username']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            $pdo = $this->setSaltPDO();
            $sql = sprintf('SELECT * FROM %s WHERE %s=?;',
                $this->options["salttable"],
                $this->options["usernamecol"]);
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$this->post['username']]);
            $salt = $stmt->fetch(PDO::FETCH_ASSOC);

            if($user[$passwordcol]
                ==crypt($this->post["password"],$salt[$saltcol])){
                $login_ok = true;
                $this->session['challengekey'] = md5($this->post["username"].$this->post["password"]);
            }
        }

        if(!empty($this->username) && $login_ok ){
            $this->setAuth($this->username);
            if( is_callable($this->loginCallback)){
                call_user_func_array($this->loginCallback,[$this->username,&$this]);
            }
        }
        if(!empty($this->username) && !$login_ok ){
            if( is_callable($this->loginFailedCallback)){
                call_user_func_array($this->loginFailedCallback,[$this->username,&$this]);
            }
        }
        if(empty($this->username) || !$login_ok){
            if(is_callable($this->loginFunction)){
                call_user_func_array($this->loginFunction,[$this->username,&$this]);
            }
        }
    }

    /**
     * @param integer   time in seconds
     * @param bool      add time to current expire time or not
     * @return void
     * @access public
     */
    function setExpire($time, $add = false){
        $add ? $this->expire += $time : $this->expire = $time;
    }

    /**
     * @param integer   time in seconds
     * @param bool      add time to current idle time or not
     * @return void
     * @access public
     */
    function setIdle($time,$add = false){
        $add ? $this->idle += $time : $this->idle = $time;
    }

    /**
     * @param string
     * @return void
     * @access public
     */
    function setCheckAuthCallback($checkAuthCallback){
        $this->checkAuthCallback = $checkAuthCallback;
    }

    /**
     * @param string
     * @return void
     * @access public
     */
    function setFailedLoginCallback($loginFailedCallback ){
        $this->loginFailedCallback = $loginFailedCallback;
    }

    /**
     * @param string
     * @return void
     * @access public
     */
    function setLoginCallback($loginCallback){
        $this->loginCallback = $loginCallback;
    }

    /**
     * @param string
     * @return void
     * @access public
     */
    function setLogoutCallback($logoutCallback){
        $this->logoutCallback = $logoutCallback;
    }

}

?>