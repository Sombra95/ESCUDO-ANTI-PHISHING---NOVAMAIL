<?php
ob_start();
ini_set('display_errors', '0');
error_reporting(E_ALL);

require_once 'conexion.php';
require_once 'crypto.php';

header('Content-Type: application/json; charset=utf-8');

function enviarRespuestaJson(array $payload, int $statusCode = 200): void {
    if (ob_get_length()) {
        ob_clean();
    }
    http_response_code($statusCode);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    enviarRespuestaJson(['success' => false, 'error' => 'Método no permitido'], 405);
}

if (!function_exists('imap_open')) {
    enviarRespuestaJson([
        'success' => false,
        'error' => 'La extensión PHP IMAP no está habilitada en php.ini (descomenta extension=imap y reinicia Apache).'
    ]);
}

try {
    $stmt = $pdo->query("SELECT * FROM configuracion_novamail LIMIT 1");
    $config = $stmt->fetch();
} catch (Exception $e) {
    enviarRespuestaJson(['success' => false, 'error' => 'Error de base de datos: ' . $e->getMessage()]);
}

if (!$config) {
    enviarRespuestaJson(['success' => false, 'error' => 'No hay configuración IMAP registrada en la base de datos.']);
}

$correo   = trim($config['correo_electronico'] ?? '');
$password = descifrarDato($config['password_token_cifrado'] ?? '');
$host     = trim($config['imap_host'] ?? '');
$puerto   = (int)($config['imap_puerto'] ?? 993);
$cifrado  = $config['imap_cifrado'] ?? 'SSL/TLS';

if (empty($correo) || empty($password) || empty($host)) {
    enviarRespuestaJson(['success' => false, 'error' => 'Faltan credenciales IMAP (host, correo o contraseña) o falló el descifrado AES-256.']);
}

$flags = "/imap";
if ($cifrado === 'SSL/TLS') {
    $flags .= "/ssl/novalidate-cert";
} elseif ($cifrado === 'STARTTLS') {
    $flags .= "/tls/novalidate-cert";
} else {
    $flags .= "/notls";
}

$mailboxString = "{" . $host . ":" . $puerto . $flags . "}INBOX";

// Evitar esperas infinitas en sockets IMAP
imap_timeout(IMAP_OPENTIMEOUT, 15);
imap_timeout(IMAP_READTIMEOUT, 15);

$conexionImap = @imap_open($mailboxString, $correo, $password, 0, 1);
if (!$conexionImap) {
    $imapErr = imap_last_error();
    imap_errors();
    imap_alerts();
    enviarRespuestaJson([
        'success' => false,
        'error' => 'Error de conexión IMAP (' . $host . ':' . $puerto . '): ' . ($imapErr ?: 'Tiempo de espera agotado o credenciales rechazadas.')
    ]);
}

$emails = @imap_search($conexionImap, 'UNSEEN');
$mensajesProcesados = [];

if ($emails && is_array($emails)) {
    rsort($emails);
    $emailsSlice = array_slice($emails, 0, 5);

    foreach ($emailsSlice as $msgIndex) {
        $headerInfo = @imap_headerinfo($conexionImap, $msgIndex);
        $cuerpoRaw  = @imap_body($conexionImap, $msgIndex);

        $asunto = isset($headerInfo->subject) ? imap_utf8($headerInfo->subject) : '(Sin asunto)';
        $remitenteObj = $headerInfo->from[0] ?? null;
        $remitenteNombre = $remitenteObj ? imap_utf8($remitenteObj->personal ?? 'Desconocido') : 'Desconocido';
        $remitenteCorreo = $remitenteObj ? ($remitenteObj->mailbox . '@' . $remitenteObj->host) : 'desconocido@domain.com';

        $textoLimpio = trim(strip_tags((string)$cuerpoRaw));
        $resumen = function_exists('mb_substr')
            ? mb_substr($textoLimpio, 0, 300, 'UTF-8')
            : substr($textoLimpio, 0, 300);

        $mensajesProcesados[] = [
            'indice'          => $msgIndex,
            'remitenteNombre' => $remitenteNombre,
            'remitenteCorreo' => $remitenteCorreo,
            'asunto'          => $asunto,
            'fecha'           => $headerInfo->date ?? date('Y-m-d H:i:s'),
            'cuerpoResumen'   => $resumen
        ];
    }
}

imap_errors();
imap_alerts();
@imap_close($conexionImap);

enviarRespuestaJson([
    'success'    => true,
    'totalBuzon' => is_array($emails) ? count($emails) : 0,
    'mensajes'   => $mensajesProcesados
]);
?>