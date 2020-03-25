<?php

/*****************************************************
* Author: Alaa E. Abdelfattah
* Company: Techledge, LLC.
* Year: 2019
*
******************************************************
*
* COPYRIGHT 2019 - Techledge, LLC
*
* This file is copyrighted and all rights
* are reserved by the author. This
* software product may be
* copied with prior consent, from the
* author.
*
******************************************************
* Techledge | SkySparkAuth Class
*
* Conducts SCRAM Authentication for SS3.
* Conducts all function/filter calls to SS3
*****************************************************/

//using .env plugin with composer, that's why I'm using this autoload file
//this is used for getting the uri, username, and password for skyspark login. 
require_once  '../../vendor/autoload.php';

class SkySpark {
	
	private $uri;
	private $username;
	private $password;
	private $serverUrl;

	function __construct() {
		$this->uri = getenv('SKYSPARK_URI'); //ex: "projUri/api/projName/eval?expr="
		$this->username = getenv('SKYSPARK_USERNAME'); //ex: username
		$this->password = getenv('SKYSPARK_PASS'); //ex: password
	}


	/*******************************************
	*										   *
	* This section is for SCRAM Authentication *
	*										   *
	*******************************************/

	/************************
	* Main SCRAM's function *
	*************************/

	function scram() {

		// the size in bytes of a SHA-256 hash
		$dklen = 32; 

		//SCRAM Autherntication Parameters
		$serverUrl = 'https://skyspark.urlProjName.com/ui';

		//Send url and username for first introduction in message 1
		$handshakeToken = $this->sendMsg1($serverUrl, $this->username);

		//Parse hanshakeToken from Server Response 1.
		$handshakeToken = $this->get_string_between($handshakeToken, '=', ',');

		//Create a random but strong id.
		$random = md5(uniqid(mt_rand(), true));

		$clientNonce = $random;

		$clientFirstMsg = "n=".$this->username.",r=".$clientNonce;

		//Send url, Client's First Message, and the hansshakeToken in message 2
		$serverFirstMsg = $this->sendMsg2($serverUrl, $clientFirstMsg,$handshakeToken);

		//Parse Server Nonce, Server Salt, and Server Iterations from Server Response 2
		$serverNonce = $this->get_string_between($serverFirstMsg, 'r=', ',');
		$serverSalt  = $this->get_string_between($serverFirstMsg, 's=', ',');
		$serverIterations = substr($serverFirstMsg, strpos($serverFirstMsg, "i=") + 2);

		//PBKDf2 for the SHA-256 hashing algorithm
		$saltedPassword = hash_pbkdf2("sha256", $this->password, base64_decode($serverSalt), intval($serverIterations), $dklen, true);

		$gs2Header = base64_encode("n,,");
		$clientFinalNoPf = 'c='.$gs2Header.',r='.$serverNonce;
		$authMessage = $clientFirstMsg.','.$serverFirstMsg.','.$clientFinalNoPf;

		//HMAC for SHA-256 hashing for the Client Key
		$clientKey = hash_hmac('sha256',"Client Key", $saltedPassword, true);

		//hash the Stored Key
		$storedKey = hash('sha256', $clientKey, true);

		//HMAC for SHA-256 hashing for the Client Signature
		$clientSignature = hash_hmac('sha256', $authMessage, $storedKey, true);

		//Xor Client Key with Client Signature
		$clientProof = ($clientKey ^ $clientSignature);

		$clientFinalMsg   = $clientFinalNoPf.",p=".base64_encode($clientProof);

		//Send url, Client's Final Message, and the hansshakeToken in message 3
		$serverSecondMsg = $this->sendMsg3($serverUrl, $clientFinalMsg,$handshakeToken);

		return $serverSecondMsg;

	}

	/***********************
	* Message 1 Using cURL *
	************************/

	function sendMsg1($serverUrl, $msg) {


		$authMsg = "HELLO username=".rtrim(strtr(base64_encode($msg), '+/', '-_'), '=');
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $serverUrl);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER  , true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array(
		    "Authorization: ". $authMsg,
		    "WWW-Authenticate: SCRAM"
		    ));
		$serverMsg = curl_exec($ch);

		curl_close($ch);

		return $serverMsg;
	}

	/***********************
	* Message 2 Using cURL *
	************************/

	function sendMsg2($serverUrl, $msg, $handshakeToken) {

		$authMsg = "SCRAM handshakeToken=".$handshakeToken.", data=".rtrim(strtr(base64_encode($msg), '+/', '-_'), '=');
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $serverUrl);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER  , true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array(
		    "Authorization: ". $authMsg,
		    "WWW-Authenticate: SCRAM"
		    ));
		$serverMsg = curl_exec($ch);
		$serverMsg = base64_decode($this->get_string_between($serverMsg,"data=",","));
		
		curl_close($ch);

	    return $serverMsg;

	}

	/***********************
	* Message 3 Using cURL *
	************************/

	function sendMsg3($serverUrl, $msg,$handshakeToken) {

		$authMsg = "SCRAM handshakeToken=".$handshakeToken.", data=".rtrim(strtr(base64_encode($msg), '+/', '-_'), '=');

		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $serverUrl);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HEADER  , true);
		curl_setopt($ch, CURLOPT_FAILONERROR, false);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array(
		    "Authorization: " .$authMsg
		    ));
		$serverMsg = curl_exec($ch);
		$serverMsg = $this->get_string_between($serverMsg,"authToken=",",");

		curl_close($ch);

	    return $serverMsg;
	}

	/******************
	* Parse function  *
	*******************/

	function get_string_between($string, $start, $end) {

	    $string = ' ' . $string;
	    $ini = strpos($string, $start);
	    if ($ini == 0) return '';
	    $ini += strlen($start);
	    $len = strpos($string, $end, $ini) - $ini;
	    return substr($string, $ini, $len);
	}
}

?>
