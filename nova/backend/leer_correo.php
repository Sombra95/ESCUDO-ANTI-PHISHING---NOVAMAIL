<?php
ob_start();
ini_set('display_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

function responderImapJson(array $payload, int $code = 200): void {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($code);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

register_shutdown_function(function () {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        responderImapJson([
            'success' => false,
            'error'   => 'Error fatal PHP en leer_correo.php: ' . $error['message'] . ' (línea ' . $error['line'] . ')'
        ], 500);
    }
});

if (!file_exists(__DIR__ . '/conexion.php') || !file_exists(__DIR__ . '/crypto.php')) {
    responderImapJson(['success' => false, 'error' => 'Faltan conexion.php o crypto.php en backend/'], 500);
}

require_once __DIR__ . '/conexion.php';
require_once __DIR__ . '/crypto.php';

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    responderImapJson(['success' => false, 'error' => 'Método no permitido'], 405);
}

if (!function_exists('imap_open')) {
    responderImapJson(['success' => false, 'error' => 'La extensión PHP IMAP no está habilitada en php.ini.']);
}

try {
    $stmt = $pdo->query("SELECT * FROM configuracion_novamail LIMIT 1");
    $config = $stmt->fetch();
} catch (Throwable $e) {
    responderImapJson(['success' => false, 'error' => 'Error de base de datos: ' . $e->getMessage()]);
}

if (!$config) {
    responderImapJson(['success' => false, 'error' => 'No hay configuración IMAP registrada.']);
}

$correo   = trim($config['correo_electronico'] ?? '');
$password = str_replace(' ', '', trim(descifrarDato($config['password_token_cifrado'] ?? '')));
$host     = trim($config['imap_host'] ?? '');
$puerto   = (int)($config['imap_puerto'] ?? 993);
$cifrado  = $config['imap_cifrado'] ?? 'SSL/TLS';

if (empty($correo) || empty($password) || empty($host)) {
    responderImapJson(['success' => false, 'error' => 'Credenciales IMAP vacías o fallo al descifrar AES-256.']);
}

// Validar longitud exacta de App Password para Gmail (16 caracteres alfabéticos)
if (stripos($host, 'gmail.com') !== false && !preg_match('/^[a-zA-Z]{16}$/', $password)) {
    responderImapJson([
        'success' => false,
        'error'   => 'Clave rechazada localmente: Gmail exige una Contraseña de Aplicación de 16 letras (la actual tiene ' . strlen($password) . ' caracteres). Genera una en myaccount.google.com/apppasswords y guárdala en Configuración.'
    ]);
}

// Protección contra reinicio de bloqueo temporal en Google
$lockFile = sys_get_temp_dir() . '/novamail_imap_cooldown_' . md5($correo) . '.lock';
if (file_exists($lockFile)) {
    $restante = (int)file_get_contents($lockFile) - time();
    if ($restante > 0) {
        $mins = ceil($restante / 60);
        responderImapJson([
            'success' => false,
            'error'   => "Protección activa: Google bloqueó temporalmente el acceso IMAP. Espera {$mins} minuto(s) más antes de reintentar para no reiniciar el bloqueo."
        ]);
    } else {
        @unlink($lockFile);
    }
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

if (function_exists('imap_timeout')) {
    @imap_timeout(IMAP_OPENTIMEOUT, 15);
    @imap_timeout(IMAP_READTIMEOUT, 15);
}

$conexionImap = @imap_open($mailboxString, $correo, $password, 0, 1);

if (!$conexionImap) {
    $imapErr = imap_last_error();
    @imap_errors();
    @imap_alerts();

    if (stripos((string)$imapErr, 'Too many login failures') !== false) {
        // Activar pausa preventiva de 12 minutos
        @file_put_contents($lockFile, (string)(time() + 720));
    }

    responderImapJson([
        'success' => false,
        'error'   => 'Error de conexión IMAP (' . $host . ':' . $puerto . '): ' . ($imapErr ?: 'Credenciales rechazadas por el servidor.')
    ]);
}

@unlink($lockFile);

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

@imap_errors();
@imap_alerts();
@imap_close($conexionImap);

responderImapJson([
    'success'    => true,
    'totalBuzon' => is_array($emails) ? count($emails) : 0,
    'mensajes'   => $mensajesProcesados
]);
?>
