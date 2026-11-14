<?php
require_once 'conexion.php';
require_once 'crypto.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Método no permitido']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
if (!$data) {
    echo json_encode(['success' => false, 'error' => 'Datos JSON inválidos']);
    exit;
}

$destinatario = $data['destinatario'] ?? '';
$asunto       = $data['asunto'] ?? '';
$mensaje      = $data['mensaje'] ?? '';

if (empty($destinatario) || empty($asunto) || empty($mensaje)) {
    echo json_encode(['success' => false, 'error' => 'Faltan campos obligatorios (destinatario, asunto, mensaje)']);
    exit;
}

try {
    $stmt = $pdo->query("SELECT correo_electronico, password_token_cifrado, smtp_host, smtp_puerto, smtp_cifrado FROM configuracion_novamail LIMIT 1");
    $config = $stmt->fetch();
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Error al consultar configuración SMTP: ' . $e->getMessage()]);
    exit;
}

if (!$config) {
    echo json_encode(['success' => false, 'error' => 'No hay configuración de correo registrada en el sistema']);
    exit;
}

$remitente = $config['correo_electronico'];
$password  = descifrarDato($config['password_token_cifrado']);
$host      = $config['smtp_host'];
$puerto    = (int)$config['smtp_puerto'];
$cifrado   = $config['smtp_cifrado'];

$remoteServer = ($cifrado === 'SSL/TLS') ? "ssl://" . $host : $host;

$socket = @stream_socket_client("$remoteServer:$puerto", $errno, $errstr, 30);
if (!$socket) {
    echo json_encode(['success' => false, 'error' => "No se pudo conectar al servidor SMTP ($errstr [$errno])"]);
    exit;
}

function leerRespuestaSmtp($socket) {
    $response = "";
    while ($line = fgets($socket, 515)) {
        $response .= $line;
        if (substr($line, 3, 1) === " ") break;
    }
    return $response;
}

leerRespuestaSmtp($socket);
fwrite($socket, "EHLO " . gethostname() . "
");
leerRespuestaSmtp($socket);

if ($cifrado === 'STARTTLS') {
    fwrite($socket, "STARTTLS
");
    $resp = leerRespuestaSmtp($socket);
    if (strpos($resp, '220') === false) {
        fclose($socket);
        echo json_encode(['success' => false, 'error' => 'El servidor rechazó STARTTLS']);
        exit;
    }
    stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    fwrite($socket, "EHLO " . gethostname() . "
");
    leerRespuestaSmtp($socket);
}

fwrite($socket, "AUTH LOGIN
");
leerRespuestaSmtp($socket);
fwrite($socket, base64_encode($remitente) . "
");
leerRespuestaSmtp($socket);
fwrite($socket, base64_encode($password) . "
");
$authResp = leerRespuestaSmtp($socket);

if (strpos($authResp, '235') === false) {
    fclose($socket);
    echo json_encode(['success' => false, 'error' => 'Autenticación SMTP fallida. Verifique sus credenciales.']);
    exit;
}

fwrite($socket, "MAIL FROM: <$remitente>
");
leerRespuestaSmtp($socket);
fwrite($socket, "RCPT TO: <$destinatario>
");
leerRespuestaSmtp($socket);
fwrite($socket, "DATA
");
leerRespuestaSmtp($socket);

$headers  = "MIME-Version: 1.0
";
$headers .= "Content-Type: text/plain; charset=utf-8
";
$headers .= "From: <$remitente>
";
$headers .= "To: <$destinatario>
";
$headers .= "Subject: =?utf-8?B?" . base64_encode($asunto) . "?=
";
$headers .= "
";

fwrite($socket, $headers . $mensaje . "
.
");
$dataResp = leerRespuestaSmtp($socket);

fwrite($socket, "QUIT
");
fclose($socket);

if (strpos($dataResp, '250') !== false) {
    echo json_encode(['success' => true, 'message' => 'Correo enviado exitosamente vía SMTP']);
} else {
    echo json_encode(['success' => false, 'error' => 'El servidor rechazó el mensaje: ' . trim($dataResp)]);
}
?>
