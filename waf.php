<?php
/*

    @author Hence/Lancet
    @time 2018.5
    @name AWD_WAF
    @version 1.0

*/


// config starts
$time=date('m_d_H_').(int)(date('i')/10);
$remote_ip = $_SERVER['REMOTE_ADDR'];

/* 
    mode 1: record malicious payload, but do nothing;
    mode 2: record malicious payload, and handle with the malicious payloads;
    mode 3: record malicious payload, and using IP waf;
    mode 4: record malicious payload, and using proxy
*/

define('WAF_MODE',4);

define('WAF_PATH','/var/www/html/my_waf/');
define('LOG_PATH','/var/www/html/my_waf/log/');
define('LOG_ALL_PATH','/var/www/html/my_waf/log_all/');
define('LOG_FILENAME',LOG_PATH."cap-".$remote_ip."-".$time.'.txt');
define('LOG_ALL_FILENAME',LOG_ALL_PATH."allcap-".$remote_ip."-".$time.'.txt');
define('LOG_HTTP',true);
define('LOG_ARGS',false);
define('ALL_RECORD',true);
define('DEBUG',false);
define('REWRITE_UPLOAD',true);
define('MALICIOUS_DIE',false);
define('MALICIOUS_UNSET',true);
define('PROXY_HOST','47.75.2.217');
define('PROXY_PORT',80);
$white_ip_list = array();
$black_ip_list = array('172.17.0.1');

// config ends

if(DEBUG){
    error_reporting(E_ERROR | E_WARNING | E_PARSE);
}

function debug_echo($msg){
    if(DEBUG){
        echo $msg;
    }
}

function debug_var_dump($msg){
    if(DEBUG){
        var_dump($msg);
    }
}

function waf(){
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_')
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
            return $headers;
        }
    }
    $get = $_GET;
    $post = $_POST;
    $cookie = $_COOKIE;
    $header = getallheaders();
    $files = $_FILES;
    $ip = $_SERVER["REMOTE_ADDR"];
    $method = $_SERVER['REQUEST_METHOD'];
    $filepath = $_SERVER["SCRIPT_NAME"];

    //if REWRITE_UPLOAD is set, rewirte shell which uploaded by others
    if(REWRITE_UPLOAD){
    	foreach ($_FILES as $key => $value) {
        	$files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
        	file_put_contents($_FILES[$key]['tmp_name'], "virink");
    	}
    }

    unset($header['Accept']);//fix a bug
    $input = array("Get"=>$get, "Post"=>$post, "Cookie"=>$cookie, "File"=>$files, "Header"=>$header);
    // the filter rules
    $pattern = "select|insert|update|delete|union|into|load_file|outfile|dumpfile|sub|hex";
    $pattern .= "admin|file_put_contents|fwrite|curl|system|eval|assert";
    $pattern .="|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern .="|`|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
    $vpattern = explode("|",$pattern);
    $bool = false;

    //if ALL_RECORD banner is set, then all the traffic is going to be recorded
    if(ALL_RECORD){
       logging($input,LOG_ALL_FILENAME);
    }

    //judge whether a data flow is malicious
    foreach ($input as $k => $v) {
        foreach($vpattern as $value){
            foreach ($v as $kk => $vv) {
                if (preg_match( "/$value/i", $vv )){
                    $bool = true;
                    if(DEBUG){
                        var_dump($value);
                        var_dump($vv);
                    }
                    logging($input,LOG_FILENAME);
                    //malicious data flow
                    return True;
                }
            }
        }
    }
    //normal data flow
    return False;
}


function logging($var,$filename)
{
    /*
    this function is used to record the traffic received by the WAF
    */

    //if LOG_ARGS is set, writing the log with the var_dump format
    if(LOG_ARGS){
        file_put_contents($filename, "\n".date("m-d H:i:s")."  ".$_SERVER['REMOTE_ADDR']."\n".print_r($var, true), FILE_APPEND);
    }

    //if LOG_HTTP is set, writing the log with the format of the basic http request
    if(LOG_HTTP){
        $http_log = "\n".$_SERVER['REQUEST_METHOD']." ".$_SERVER['REQUEST_URI']." HTTP/1.1\n";
        foreach(getallheaders() as $key => $value){
            $http_log .=   $key.": ".$value."\n";
        }
        $is_first = true;
        $http_log .= "\n";
        foreach($_POST as $key => $value){
            if(!$is_first){ $http_log .= '&';}
            $http_log .= $key."=".$value;
            $is_first = false;
        }
        file_put_contents($filename, $http_log,  FILE_APPEND);
    }
}

function handle_malicious($msg='I am waf;go die'){
    /*
    this function is used to handle with situation where the malicious payloads are found
    */

    //if MALICIOUS_UNSET is set, unset all the super global variables
    if(MALICIOUS_UNSET){
        unset($_GET);
        unset($_POST);
        unset($_COOKIE);
        unset($_REQUEST);
    }
    //if MALICIOUS_DIE, then go die
    if(MALICIOUS_DIE){
	    debug_echo($msg);
        die();
    }
}

function ip_waf()
{
    global $white_ip_list,$black_ip_list,$remote_ip;
    
    //if the white_ip_list is set, then receiving the traffic from the ip in the white_ip_list only
    // and the priority of the white list is higher than black list
    if(count($white_ip_list)>0){
        if(!in_array($remote_ip,$white_ip_list)){
            handle_malicious('403 forbidden');
        }
    }else if(count($black_ip_list)>0){
        if(in_array($remote_ip, $black_ip_list)){
            handle_malicious('403 forbidden');
        }
    }
}

function proxy($host,$port,$malicious){
    /*
    this function is used forward the traffic to other server, just like a transparent proxy
    */

    //get basic info
    $method = $_SERVER['REQUEST_METHOD'];
    $url = 'http://' . $host .':'. $port . $_SERVER['REQUEST_URI'];
    $query = $_SERVER['QUERY_STRING'];
    $headers = getallheaders();
    $body = file_get_contents('php://input');
    foreach($_POST as $key=>$value){
        $data[$key] = $value;
    }
    foreach($_GET as $key=>$value){
        $data[$key] = $value;
    }
    foreach($_COOKIE as $key=>$value){
        $data[$key] = $value;
    }
    debug_echo('#### proxy request starts #####');
    debug_var_dump($headers);
    debug_var_dump($body);
    debug_echo('#### proxy request ends #####');

    //send request
    //change the header of host to the value of the real server
    $headers['HOST'] = $host .':'. $port;
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl,CURLOPT_POSTFIELDS,$body);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($curl, CURLOPT_HEADER,1);
    if($method=='GET'){
        ;
    }else if($method=='POST'){
        curl_setopt($curl,CURLOPT_POST,1);
    }else{
        exit('unknown method: '.$method);
    }
    $res = curl_exec($curl);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);

    // record the server response according to the config
    if($malicious){
        file_put_contents(LOG_FILENAME, "\n".str_replace("\r", "", $res)."\n", FILE_APPEND);
    }
    if(ALL_RECORD){
        file_put_contents(LOG_ALL_FILENAME, "\n".str_replace("\r", "", $res)."\n", FILE_APPEND);
    }

    $response_headers = substr($res, 0, $headerSize);
    $response_body = substr($res, $headerSize);
    curl_close($curl);
    debug_echo('#### proxy reply starts #####');
    debug_var_dump($response_headers);
    debug_var_dump($response_body);
    debug_echo('#### proxy reply ends #####');

    //update the headers
    $tmp = array_slice(explode("\r\n",$response_headers),1);
    foreach($tmp as $line){
        if($line!==''&& !strstr($line,"Transfer-Encoding")){
            //list($key,$value) = explode(":",$line,2);
            header($line);
        }
    }

    //output the body
    echo $response_body;
    exit();
    
}

switch (WAF_MODE) {
    case 1:
        if(waf()){;}
        break;

    case 2:
        if(waf()){handle_malicious();}
        break;

    case 3:
        if(waf()){ip_waf();}
        break;

    case 4:
        $m = waf();
        proxy(PROXY_HOST,PROXY_PORT,$m);
        break;
    
    default:
        exit('no such mode!');
        break;
}

?>
