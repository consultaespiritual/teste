<?php
// --- Configurações ---
$logFile = '/home/ubuntu/security_log.txt'; // Caminho para o arquivo de log
$enableLogging = true; // Mudar para false para desativar logs
$fakePagePath = '/home/ubuntu/upload/fake.html'; // Caminho para a página fake
$realPagePath = '/home/ubuntu/index_v2.html'; // Caminho para a página real (nova versão)

// --- Funções Auxiliares ---

/**
 * Registra uma tentativa de acesso bloqueada.
 * @param string $ip
 * @param string $userAgent
 * @param string $reason
 */
function logBlockedAccess($ip, $userAgent, $reason) {
    global $logFile, $enableLogging;
    if (!$enableLogging) return;

    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "{$timestamp} | IP: {$ip} | UA: {$userAgent} | Reason: {$reason}\n";
    
    // Usar file_put_contents com LOCK_EX para escrita segura
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

/**
 * Verifica se o User-Agent corresponde a padrões de bots conhecidos ou suspeitos.
 * @param string $userAgent
 * @return bool
 */
function isBotUserAgent($userAgent) {
    // Regex mais abrangente para bots comuns e padrões suspeitos
    // Inclui: facebook, google, bing, slurp, duckduck, baidu, yandex, sogou, Ahrefs, SEMrush, Majestic, DotBot, PetalBot, etc.
    // Também procura por padrões comuns como 'bot', 'spider', 'crawler', 'headless'
    $botPattern = '/(facebookexternalhit|Facebot|Googlebot|AdsBot-Google|Google-InspectionTool|FeedFetcher-Google|bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|Sogou|AhrefsBot|SEMrushBot|MJ12bot|DotBot|PetalBot|Bytespider|MegaIndex|BLEXBot|crawler|spider|bot|headless|python-requests|curl|wget|http-client)/i';
    
    return preg_match($botPattern, $userAgent) === 1;
}

/**
 * Verifica se o IP pertence a faixas conhecidas de data centers ou proxies (Exemplo Conceitual).
 * NOTA: Esta é uma implementação MUITO simplificada. Uma solução real requer bases de dados atualizadas ou APIs externas.
 * @param string $ip
 * @return bool
 */
function isSuspiciousIP($ip) {
    // Exemplos de faixas de IP (NÃO USAR EM PRODUÇÃO - apenas ilustrativo)
    $suspiciousRanges = [
        '69.63.', '66.220.', '66.249.', '31.13.', // Facebook & Google (mantidos do original)
        '157.55.', // Microsoft/Bing
        '52.', '34.', '35.', // AWS
        '104.196.', '104.154.', // Google Cloud
        '40.74.', '13.64.', // Azure
        // Adicionar mais faixas conhecidas de data centers, VPNs, TOR exit nodes se possível
    ];

    foreach ($suspiciousRanges as $range) {
        if (strpos($ip, $range) === 0) {
            return true;
        }
    }
    
    // Placeholder para integração com API de Reputação de IP (ex: IPQualityScore, MaxMind)
    /*
    $apiKey = 'SUA_API_KEY_AQUI';
    $url = "https://www.ipqualityscore.com/api/json/ip/{$apiKey}/{$ip}";
    $response = @file_get_contents($url);
    if ($response) {
        $data = json_decode($response, true);
        // Verificar flags como 'is_crawler', 'vpn', 'tor', 'proxy', 'abuse_velocity', 'fraud_score' > threshold
        if ($data && ($data['proxy'] || $data['vpn'] || $data['tor'] || $data['is_crawler'] || $data['fraud_score'] > 85)) {
            return true;
        }
    }
    */

    return false;
}

/**
 * Verifica cabeçalhos HTTP por anomalias.
 * @return bool
 */
function hasSuspiciousHeaders() {
    // Verifica ausência de cabeçalhos comuns de navegadores
    if (!isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) || empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        return true; // Navegadores reais geralmente enviam Accept-Language
    }
    if (!isset($_SERVER['HTTP_ACCEPT']) || strpos($_SERVER['HTTP_ACCEPT'], 'text/html') === false) {
        return true; // Navegadores reais geralmente aceitam text/html
    }
    
    // Verifica Referer (com cautela, pode ser omitido ou falsificado)
    // Se o tráfego DEVE vir de um domínio específico (ex: facebook.com), pode adicionar uma verificação aqui.
    /*
    if (isset($_SERVER['HTTP_REFERER'])) {
        $refererHost = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
        if (strpos($refererHost, 'facebook.com') === false && strpos($refererHost, 'instagram.com') === false) {
             // Logar e talvez bloquear, dependendo da estratégia
        }
    } else {
        // Ausência de Referer pode ser suspeita dependendo do contexto
    }
    */

    // Outras verificações possíveis: DNT (Do Not Track), X-Forwarded-For (se atrás de proxy)

    return false;
}

// --- Lógica Principal ---

$userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
$isBlocked = false;
$blockReason = '';

// 1. Verificação de User-Agent
if (isBotUserAgent($userAgent)) {
    $isBlocked = true;
    $blockReason = 'Bot User-Agent Detected';
}

// 2. Verificação de IP (Conceitual)
if (!$isBlocked && isSuspiciousIP($ip)) {
    // Decidir se bloqueia ou apenas loga IPs suspeitos
    // Para maior segurança, bloquear:
    $isBlocked = true;
    $blockReason = 'Suspicious IP Range/Reputation';
    // Para ser menos agressivo, apenas logar:
    // logBlockedAccess($ip, $userAgent, 'Suspicious IP Range/Reputation (Logged Only)');
}

// 3. Verificação de Cabeçalhos
if (!$isBlocked && hasSuspiciousHeaders()) {
    $isBlocked = true;
    $blockReason = 'Suspicious HTTP Headers';
}

// --- Ação Final ---

if ($isBlocked) {
    // Loga o bloqueio
    logBlockedAccess($ip, $userAgent, $blockReason);
    
    // Serve a página fake diretamente (mais discreto que redirect)
    // Garante que o caminho para fake.html está correto
    if (file_exists($fakePagePath)) {
        // Define um código de status HTTP apropriado (opcional, 200 OK é mais discreto)
        // http_response_code(403); // Forbidden
        include($fakePagePath);
    } else {
        // Fallback caso a página fake não exista
        http_response_code(404); // Not Found
        echo "Content not available.";
    }
    exit; // Interrompe a execução
} else {
    // Usuário real: carrega conteúdo real (nova versão)
    // Garante que o caminho para index_v2.html está correto
    if (file_exists($realPagePath)) {
        include($realPagePath);
    } else {
        http_response_code(500); // Internal Server Error
        echo "Error loading page content.";
        // Logar esse erro também seria útil
        logBlockedAccess($ip, $userAgent, 'Error: Real page file not found (' . $realPagePath . ')');
    }
    exit;
}

?>
