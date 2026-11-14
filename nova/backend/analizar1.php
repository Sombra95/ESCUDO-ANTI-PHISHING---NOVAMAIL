<?php
require_once 'conexion.php';
require_once 'crypto.php';

header('Content-Type: application/json; charset=utf-8');
$method = $_SERVER['REQUEST_METHOD'];

if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Método no permitido']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
if (!$data) {
    echo json_encode(['success' => false, 'error' => 'Payload JSON inválido o vacío']);
    exit;
}

try {
    $stmtConfig = $pdo->query("SELECT modelo_ia, api_key_ia_cifrada, escaneo_preventivo_activo FROM configuracion_novamail LIMIT 1");
    $config = $stmtConfig->fetch();
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => 'Error al leer configuración: ' . $e->getMessage()]);
    exit;
}

if (!$config || empty($config['api_key_ia_cifrada'])) {
    echo json_encode(['success' => false, 'error' => 'API Key de IA no configurada en el sistema']);
    exit;
}

if ((int)$config['escaneo_preventivo_activo'] === 0) {
    echo json_encode(['success' => true, 'mensaje' => 'Escaneo preventivo desactivado por el usuario']);
    exit;
}

$apiKey = descifrarDato($config['api_key_ia_cifrada']);
if (empty($apiKey)) {
    echo json_encode(['success' => false, 'error' => 'No se pudo descifrar la API Key de IA.']);
    exit;
}

$remitenteNombre    = $data['remitenteNombre'] ?? 'Desconocido';
$remitenteCorreo    = $data['remitenteCorreo'] ?? 'desconocido@dominio.com';
$destinatarioCorreo = $data['destinatarioCorreo'] ?? 'admin@novamail.ai';
$asunto             = $data['asunto'] ?? '(Sin asunto)';
$cuerpo             = $data['cuerpo'] ?? '';
$cabecerasRaw       = $data['cabecerasRaw'] ?? '';
$ipOrigen           = $data['ipOrigen'] ?? '0.0.0.0';
$hostingOrigen      = $data['hostingOrigen'] ?? 'No identificado';
$asn                = $data['asn'] ?? null;
$pais               = $data['pais'] ?? 'Desconocido';

$modelo = $config['modelo_ia'] ?: 'gemini-3.8-flash';
$url    = "https://generativelanguage.googleapis.com/v1beta/models/" . urlencode($modelo) . ":generateContent?key=" . urlencode($apiKey);

$promptSistema = <<<EOT
Eres un motor de ciberseguridad especializado en análisis forense de correos electrónicos y detección de phishing.
Analiza los siguientes metadatos y contenido de un correo entrante:
- Remitente Nombre: {$remitenteNombre}
- Remitente Correo: {$remitenteCorreo}
- IP de Origen: {$ipOrigen}
- Proveedor Hosting/ASN: {$hostingOrigen} ({$asn})
- Asunto: {$asunto}
- Cuerpo: {$cuerpo}
- Cabeceras: {$cabecerasRaw}

Evalúa spoofing de dominio, ingeniería social, urgencia artificial, enlaces sospechosos y reputación de infraestructura.
Responde ÚNICAMENTE con un objeto JSON válido con la siguiente estructura exacta:
{
  "esPhishing": boolean,
  "nivelRiesgo": "BAJO" | "MEDIO" | "ALTO" | "CRITICO",
  "puntuacionConfianza": float (entre 0.00 y 100.00),
  "indicadores": ["lista", "de", "hallazgos", "tecnicos"]
}
EOT;

$payload = json_encode([
    "contents" => [
        ["parts" => [["text" => $promptSistema]]]
    ],
    "generationConfig" => [
        "temperature" => 0.1,
        "responseMimeType" => "application/json"
    ]
]);

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($curlError || $httpCode !== 200) {
    echo json_encode([
        'success' => false,
        'error' => 'Fallo en la comunicación con el motor de IA',
        'detalle' => $curlError ?: json_decode($response, true)
    ]);
    exit;
}

$apiResult   = json_decode($response, true);
$rawText     = $apiResult['candidates'][0]['content']['parts'][0]['text'] ?? '{}';
$iaVeredicto = json_decode($rawText, true);

if (!is_array($iaVeredicto) || !isset($iaVeredicto['esPhishing'])) {
    echo json_encode(['success' => false, 'error' => 'Respuesta malformada del modelo de IA']);
    exit;
}

$esPhishing  = (bool)$iaVeredicto['esPhishing'];
$nivelRiesgo = in_array($iaVeredicto['nivelRiesgo'] ?? '', ['BAJO', 'MEDIO', 'ALTO', 'CRITICO']) 
               ? $iaVeredicto['nivelRiesgo'] 
               : ($esPhishing ? 'ALTO' : 'BAJO');
$confianza   = isset($iaVeredicto['puntuacionConfianza']) ? (float)$iaVeredicto['puntuacionConfianza'] : 0.00;
$indicadores = is_array($iaVeredicto['indicadores'] ?? null) ? $iaVeredicto['indicadores'] : [];

$resultadoAnalisis = [
    'esPhishing'         => $esPhishing,
    'remitenteNombre'    => $remitenteNombre,
    'remitenteCorreo'    => $remitenteCorreo,
    'destinatarioCorreo' => $destinatarioCorreo,
    'asunto'             => $asunto,
    'cuerpoResumen'      => mb_substr($cuerpo, 0, 500),
    'ipOrigen'           => $ipOrigen,
    'hostingOrigen'      => $hostingOrigen,
    'asn'                => $asn,
    'pais'               => $pais,
    'riesgo'             => $nivelRiesgo,
    'confianza'          => $confianza,
    'modelo'             => $modelo,
    'indicadores'        => $indicadores
];

if ($esPhishing) {
    try {
        $uuid = 'PHISH-' . strtoupper(bin2hex(random_bytes(4)));
        $indicadoresJson = json_encode($indicadores, JSON_UNESCAPED_UNICODE);

        $sql = "INSERT INTO registros_phishing_remoto 
                (uuid_incidente, remitente_nombre, remitente_correo, destinatario_correo, asunto, 
                 cuerpo_resumen, direccion_ip_origen, proveedor_hosting, asn_numero, pais_origen,
                 cabeceras_raw, es_phishing, nivel_riesgo, puntuacion_confianza, modelo_ia_utilizado, 
                 indicadores_detectados, estado_accion)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'CUARENTENA')";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            $uuid,
            $remitenteNombre,
            $remitenteCorreo,
            $destinatarioCorreo,
            $asunto,
            $resultadoAnalisis['cuerpoResumen'],
            $ipOrigen,
            $hostingOrigen,
            $asn,
            $pais,
            $cabecerasRaw,
            $nivelRiesgo,
            $confianza,
            $modelo,
            $indicadoresJson
        ]);
        $resultadoAnalisis['uuidIncidente'] = $uuid;
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'error' => 'Amenaza detectada, pero falló el registro en BD: ' . $e->getMessage(),
            'analisis' => $resultadoAnalisis
        ]);
        exit;
    }
}

echo json_encode(['success' => true, 'analisis' => $resultadoAnalisis]);
?>
