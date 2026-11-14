<?php
// Clave maestra de 32 bytes (256 bits) - Cambiar por una variable de entorno en producción
define('NOVAMAIL_MASTER_KEY', hash('sha256', 'CambiaEstaClaveSecreta_NovaMailAI_2026!', true));
define('NOVAMAIL_CIPHER', 'aes-256-gcm');

function cifrarDato(?string $textoPlano): string {
    if (empty($textoPlano)) {
        return '';
    }
    $ivLen = openssl_cipher_iv_length(NOVAMAIL_CIPHER);
    $iv = random_bytes($ivLen);
    $tag = '';

    $cifrado = openssl_encrypt(
        $textoPlano,
        NOVAMAIL_CIPHER,
        NOVAMAIL_MASTER_KEY,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    return base64_encode($iv . $tag . $cifrado);
}

function descifrarDato(?string $payloadBase64): string {
    if (empty($payloadBase64)) {
        return '';
    }
    $raw = base64_decode($payloadBase64, true);
    if ($raw === false) {
        return '';
    }

    $ivLen = openssl_cipher_iv_length(NOVAMAIL_CIPHER);
    $tagLen = 16;

    if (strlen($raw) <= ($ivLen + $tagLen)) {
        return '';
    }

    $iv = substr($raw, 0, $ivLen);
    $tag = substr($raw, $ivLen, $tagLen);
    $cifrado = substr($raw, $ivLen + $tagLen);

    $descifrado = openssl_decrypt(
        $cifrado,
        NOVAMAIL_CIPHER,
        NOVAMAIL_MASTER_KEY,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    return $descifrado !== false ? $descifrado : '';
}
?>
