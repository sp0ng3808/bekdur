<?php

function calculator($firstNum, $secondNum, $operation)
{
	switch ($operation) {
		case '+':
			$hasil = $firstNum + $secondNum;
			break;
		case '-':
			$hasil = $firstNum - $secondNum;
			break;
		case 'x':
			$hasil = $firstNum * $secondNum;
			break;
		case '/':
			$hasil = $firstNum / $secondNum;
			break;
		default:
			$hasil = "Operasi Salah !";
			break;
	} return $hasil;
}

$value = (isset($_POST['input'])) ? $_POST['input'] : "";

?>
<form method="post">
	<input type="text" name="input" placeholder="1 + 3" value="<?= $value ?>">
	<input type="submit" name="execute" value="calculating">
</form>

<?php

if (isset($_POST["execute"])) {
	$imm = explode(" ", $_POST['input']);
	
	$firstNum = $imm[0];
	$operation = $imm[1];
	$secondNum = $imm[2];

	echo calculator($firstNum, $secondNum, $operation);
}