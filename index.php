<?php

ob_start();
session_start();

require('db.inc.php');

if ( isset( $_POST['actionflag'] ) && $_POST['actionflag'] == "login" )
{
	if ( empty( $_POST['username']) || empty( $_POST['password']) )
	{		
		$error_message[] = "Morate popuniti sva polja";
	}
	else
	{		
		$username = $_POST['username'];
		$password = crypt($_POST['password'], md5($_POST['username']));

		try {
			$stmt = $conn->prepare('SELECT id, username, password FROM users WHERE username = :username AND password = :password');
			$stmt->execute(array('username' => $username, 'password' => $password));
			$row = $stmt->fetch();

		} catch(PDOException $e) {
		    $error_message[] =$e->getMessage();
		}

		if($row)
		{
			$_SESSION['user_id'] = $row['id'];
			$_SESSION['username'] = $row['username'];
			$_SESSION['password'] = $row['password'];
			$_SESSION['logged_in'] = true;
			
			header('Location: index.php');
			exit;
		}
		else
		{
			$error_message[] = "Neispravna prijava, pokusajte ponovo!";
		}
	}
}
elseif ( isset( $_POST['actionflag'] ) && $_POST['actionflag'] == "register" ) 
{
	if(strlen($_POST['username']) < 3) {
		$error_message[] = 'Previse kratak username.';
	} else {
		$stmt = $conn->prepare('SELECT username FROM users WHERE username = :username');
		$stmt->execute(array(':username' => $_POST['username']));
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if(!empty($row['username'])){
			$error_message[] = 'Username vec postoji.';
		}
	}

	if(strlen($_POST['password']) < 3) {
		$error_message[] = 'Previse kratak password.';
	}

	if(strlen($_POST['confirm-password']) < 3) {
		$error_message[] = 'Previse kratak confirm password.';
	}

	if($_POST['password'] != $_POST['confirm-password']) {
		$error_message[] = 'Passwordi se ne poklapaju.';
	}

	if(empty( $_POST['email'])) {
		$error_message[] = 'Niste uneli email.';
	}

	if(!isset($error_message)){
		
		// jednostavan, slab hash passworda
		$hashed_password = crypt($_POST['password'], md5($_POST['username']));

		try {
			$stmt = $conn->prepare('INSERT INTO users (username,password,email) VALUES (:username, :password, :email)');
			$stmt->execute(array(
				':username' => $_POST['username'],
				':password' => $hashed_password,
				':email' => $_POST['email']
			));
			header('Location: index.php?action=joined');
			exit;
		} catch(PDOException $e) {
		    $error_message[] = $e->getMessage();
		}
	}
}
elseif ( isset( $_GET['actionflag'] ) && $_GET['actionflag'] == "logout" )
{
	session_destroy();
	header('Location: index.php');
	exit;
}


?>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Demo app</title>
	<link rel="stylesheet" type="text/css" href="main.css">
</head>
<body>
	<div class="main">
		<?php
			if(isset($error_message)) {
				echo '<div class="info-box"><ul>';
					foreach($error_message as $error) {
						echo '<li>' . $error . '</li>';
					}
					echo '</ul></div>';
				}
		?>
		<?php
			if(isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true)
			{
		?>
				<header>
					<nav class="main-nav">
						<ul>
							<li><a href="index.php?action=home">home</a></li>
							<li><a href="index.php?action=list-all-users">list all users</a></li>
							<li><a href="index.php?actionflag=logout">logout</a></li>
						</ul>
					</nav>
				</header>
		<?php
				$body = "Hello " . $_SESSION['username'];
				if(isset($_GET['action'])){
					switch ($_GET['action']) {
						case 'list-all-users':
							$qry = "SELECT * FROM users ORDER BY created_at";
							$stmt = $conn->query($qry);
							$user_rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

							$body = "<ul>";
							foreach ($user_rows as $user_row) {
								$body .= '<li>' . 'ID: ' . $user_row["id"] . ' USERNAME: ' . $user_row["username"] . ' EMAIL: ' . $user_row["email"] . ' CREATED_AT: ' . $user_row["created_at"] . '</li>';
							}
							$body .= "</ul>";
							break;
						case 'home':
						default:
							$body = "Hello " . $_SESSION['username'];
							break;
					}
				}

				echo '<div class="main">' . $body . '</div>';
			} elseif (isset($_GET['action']) && $_GET['action'] == 'joined') {
		?>
				<h1>Registracija uspesna!</h1>
				<div class="main">
					<h1>Login</h1>
					<form action="index.php" method="POST">
						<input type="hidden" name="actionflag" value="login">
						<div class="input-group">
							<label for="username">Username</label>
							<input type="text" name="username" id="username">
						</div>
						<div class="input-group">
							<label for="password">Password</label>
							<input type="password" name="password" id="password">
						</div>
						<button type="submit" class="btn">Login</button>
					</form>
				</div>
		<?php
			} elseif ( (isset($_GET['action']) && $_GET['action'] == 'register') || (isset( $_POST['actionflag'] ) && $_POST['actionflag'] == "register")) {
		?>
				<div class="main">
					<h1>Register</h1>
					<form action="index.php" method="POST">
						<input type="hidden" name="actionflag" value="register">
						<div class="input-group">
							<label for="username">Username</label>
							<input type="text" name="username" id="username">
						</div>
						<div class="input-group">
							<label for="password">Password</label>
							<input type="password" name="password" id="password">
						</div>
						<div class="input-group">
							<label for="confirm-password">Confirm Password</label>
							<input type="password" name="confirm-password" id="confirm-password">
						</div>
						<div class="input-group">
							<label for="email">E-mail</label>
							<input type="text" name="email" id="email">
						</div>
						<button type="submit" class="btn">Register</button>
					</form>
				</div>
		<?php
			}
			else
			{
		?>
				<div class="main">
					<h1>Login</h1>
					<form action="index.php" method="POST">
						<input type="hidden" name="actionflag" value="login">
						<div class="input-group">
							<label for="username">Username</label>
							<input type="text" name="username" id="username">
						</div>
						<div class="input-group">
							<label for="password">Password</label>
							<input type="password" name="password" id="password">
						</div>
						<button type="submit" class="btn">Login</button>
					</form>
				</div>
		<div class="main">
			<a href="index.php?action=register">Register</a>
		</div>
		<?php
			} //end else
		?>
	</div>
</body>
</html>
