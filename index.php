<?php
session_start();

// Массив сообщений для разных языков
$messages = [
    'ru' => [
        'title' => "Отключение ECH и IPv6 в Cloudflare",
        'api_key_label' => "Global API Key:",
        'zone_id_label' => "Zone ID:",
        'email_label' => "Email:",
        'ech_checkbox' => "Проверить и отключить ECH",
        'ipv6_checkbox' => "Проверить и отключить IPv6",
        'submit_button' => "Проверить и отключить",
        'result_title' => "Результат:",
        'status' => "Текущий статус ECH: %s",
        'disabling' => "Отключаем ECH...",
        'success' => "ECH успешно отключен",
        'already_off' => "ECH уже отключен, никаких действий не требуется",
        'ipv6_status' => "Текущий статус IPv6: %s",
        'ipv6_disabling' => "Отключаем IPv6...",
        'ipv6_success' => "IPv6 успешно отключен",
        'ipv6_already_off' => "IPv6 уже отключен, никаких действий не требуется",
        'not_found' => "Настройка %s не найдена в списке настроек.",
        'debug' => "Все настройки зоны для отладки:",
        'error' => "Ошибка: %s",
        'csrf_error' => "Ошибка проверки CSRF-токена",
        'empty_fields' => "Пожалуйста, заполните все поля",
        'bot_detected' => "Доступ заблокирован: запрос не прошёл через Cloudflare или подозрительный трафик",
        'turnstile_error' => "Ошибка проверки Turnstile: %s"
    ],
    'en' => [
        'title' => "Disable ECH and IPv6 in Cloudflare",
        'api_key_label' => "Global API Key:",
        'zone_id_label' => "Zone ID:",
        'email_label' => "Email:",
        'ech_checkbox' => "Check and disable ECH",
        'ipv6_checkbox' => "Check and disable IPv6",
        'submit_button' => "Check and Disable",
        'result_title' => "Result:",
        'status' => "Current ECH status: %s",
        'disabling' => "Disabling ECH...",
        'success' => "ECH successfully disabled",
        'already_off' => "ECH is already disabled, no action needed",
        'ipv6_status' => "Current IPv6 status: %s",
        'ipv6_disabling' => "Disabling IPv6...",
        'ipv6_success' => "IPv6 successfully disabled",
        'ipv6_already_off' => "IPv6 is already disabled, no action needed",
        'not_found' => "Setting %s not found in the settings list.",
        'debug' => "All zone settings for debugging:",
        'error' => "Error: %s",
        'csrf_error' => "CSRF token verification failed",
        'empty_fields' => "Please fill in all fields",
        'bot_detected' => "Access denied: request did not pass through Cloudflare or suspicious traffic",
        'turnstile_error' => "Turnstile verification error: %s"
    ]
];

// Определение языка
function detectLanguage() {
    $defaultLang = 'en';
    $supportedLangs = ['ru', 'en'];
    
    if (isset($_SESSION['language'])) {
        return $_SESSION['language'];
    }
    
    $acceptLang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if ($acceptLang) {
        $langs = explode(',', $acceptLang);
        foreach ($langs as $lang) {
            $langCode = strtolower(substr($lang, 0, 2));
            if (in_array($langCode, $supportedLangs)) {
                return $langCode;
            }
        }
    }
    
    return $defaultLang;
}

$language = isset($_GET['lang']) && in_array($_GET['lang'], ['ru', 'en']) ? $_GET['lang'] : detectLanguage();
$_SESSION['language'] = $language;

// Ключи <?php
session_start();

// Массив сообщений для разных языков
$messages = [
    'ru' => [
        'title' => "Отключение ECH и IPv6 в Cloudflare",
        'api_key_label' => "Global API Key:",
        'zone_id_label' => "Zone ID:",
        'email_label' => "Email:",
        'ech_checkbox' => "Проверить и отключить ECH",
        'ipv6_checkbox' => "Проверить и отключить IPv6",
        'submit_button' => "Проверить и отключить",
        'result_title' => "Результат:",
        'status' => "Текущий статус ECH: %s",
        'disabling' => "Отключаем ECH...",
        'success' => "ECH успешно отключен",
        'already_off' => "ECH уже отключен, никаких действий не требуется",
        'ipv6_status' => "Текущий статус IPv6: %s",
        'ipv6_disabling' => "Отключаем IPv6...",
        'ipv6_success' => "IPv6 успешно отключен",
        'ipv6_already_off' => "IPv6 уже отключен, никаких действий не требуется",
        'not_found' => "Настройка %s не найдена в списке настроек.",
        'debug' => "Все настройки зоны для отладки:",
        'error' => "Ошибка: %s",
        'csrf_error' => "Ошибка проверки CSRF-токена",
        'empty_fields' => "Пожалуйста, заполните все поля",
        'bot_detected' => "Доступ заблокирован: запрос не прошёл через Cloudflare или подозрительный трафик",
        'turnstile_error' => "Ошибка проверки Turnstile: %s"
    ],
    'en' => [
        'title' => "Disable ECH and IPv6 in Cloudflare",
        'api_key_label' => "Global API Key:",
        'zone_id_label' => "Zone ID:",
        'email_label' => "Email:",
        'ech_checkbox' => "Check and disable ECH",
        'ipv6_checkbox' => "Check and disable IPv6",
        'submit_button' => "Check and Disable",
        'result_title' => "Result:",
        'status' => "Current ECH status: %s",
        'disabling' => "Disabling ECH...",
        'success' => "ECH successfully disabled",
        'already_off' => "ECH is already disabled, no action needed",
        'ipv6_status' => "Current IPv6 status: %s",
        'ipv6_disabling' => "Disabling IPv6...",
        'ipv6_success' => "IPv6 successfully disabled",
        'ipv6_already_off' => "IPv6 is already disabled, no action needed",
        'not_found' => "Setting %s not found in the settings list.",
        'debug' => "All zone settings for debugging:",
        'error' => "Error: %s",
        'csrf_error' => "CSRF token verification failed",
        'empty_fields' => "Please fill in all fields",
        'bot_detected' => "Access denied: request did not pass through Cloudflare or suspicious traffic",
        'turnstile_error' => "Turnstile verification error: %s"
    ]
];

// Определение языка
function detectLanguage() {
    $defaultLang = 'en';
    $supportedLangs = ['ru', 'en'];
    
    if (isset($_SESSION['language'])) {
        return $_SESSION['language'];
    }
    
    $acceptLang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if ($acceptLang) {
        $langs = explode(',', $acceptLang);
        foreach ($langs as $lang) {
            $langCode = strtolower(substr($lang, 0, 2));
            if (in_array($langCode, $supportedLangs)) {
                return $langCode;
            }
        }
    }
    
    return $defaultLang;
}

$language = isset($_GET['lang']) && in_array($_GET['lang'], ['ru', 'en']) ? $_GET['lang'] : detectLanguage();
$_SESSION['language'] = $language;

// Ключи Turnstile
$turnstileSiteKey = 'yourSiteKey?????????????????';
$turnstileSecretKey = 'yourturnstileSecretKey???????????????????????';

// Проверка защиты от ботов через Cloudflare
function checkBotProtection($messages, $language) {
    $cfRay = isset($_SERVER['HTTP_CF_RAY']) ? $_SERVER['HTTP_CF_RAY'] : null;
    if (!$cfRay) {
        return $messages[$language]['bot_detected'];
    }
    return null;
}

// Проверка Turnstile токена
function verifyTurnstile($token, $secretKey, $messages, $language) {
    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $data = [
        'secret' => $secretKey,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        curl_close($ch);
        return sprintf($messages[$language]['turnstile_error'], "cURL error: " . curl_error($ch));
    }
    curl_close($ch);

    $result = json_decode($response, true);
    if ($result === null || !isset($result['success'])) {
        return sprintf($messages[$language]['turnstile_error'], "Invalid response from Turnstile API");
    }
    if ($result['success'] === false) {
        return sprintf($messages[$language]['turnstile_error'], implode(', ', $result['error-codes'] ?? ['Unknown error']));
    }
    return null;
}

// Проверка формы и API-запросов
function processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language) {
    if (!preg_match('/^[a-zA-Z0-9]{37}$/', $apiKey)) {
        return sprintf($messages[$language]['error'], "Invalid Global API Key format.") . "<br>";
    }
    if (!preg_match('/^[a-f0-9]{32}$/', $zoneId)) {
        return sprintf($messages[$language]['error'], "Invalid Zone ID format.") . "<br>";
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return sprintf($messages[$language]['error'], "Invalid email format.") . "<br>";
    }

    $url = "https://api.cloudflare.com/client/v4/zones/{$zoneId}/settings";
    
    function makeApiRequest($url, $apiKey, $email, $method = 'GET', $data = null) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        
        $headers = [
            'X-Auth-Email: ' . trim($email),
            'X-Auth-Key: ' . trim($apiKey),
            'Content-Type: application/json'
        ];
        
        if ($method === 'PATCH' && $data) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            return ['success' => false, 'message' => "cURL Error: $error"];
        }
        
        curl_close($ch);
        return ['success' => true, 'code' => $httpCode, 'response' => json_decode($response, true)];
    }

    $checkResult = makeApiRequest($url, $apiKey, $email);
    $output = '';

    if ($checkResult['success'] && $checkResult['code'] == 200 && $checkResult['response']['success']) {
        $settings = $checkResult['response']['result'];
        
        // Проверка ECH
        $echStatus = null;
        $ipv6Status = null;
        foreach ($settings as $setting) {
            if (isset($setting['id']) && $setting['id'] === 'ech') {
                $echStatus = $setting['value'];
            }
            if (isset($setting['id']) && $setting['id'] === 'ipv6') {
                $ipv6Status = $setting['value'];
            }
        }

        // Обработка ECH
        if ($disableECH) {
            if ($echStatus === null) {
                $output .= sprintf($messages[$language]['not_found'], 'ECH (ech)') . "<br>";
            } else {
                $output .= sprintf($messages[$language]['status'], htmlspecialchars($echStatus)) . "<br>";
                if ($echStatus !== 'off') {
                    $output .= $messages[$language]['disabling'] . "<br>";
                    $patchData = [
                        'items' => [
                            [
                                'id' => 'ech',
                                'value' => 'off'
                            ]
                        ]
                    ];
                    $patchResult = makeApiRequest($url, $apiKey, $email, 'PATCH', $patchData);
                    if ($patchResult['success'] && $patchResult['code'] == 200 && $patchResult['response']['success']) {
                        $output .= $messages[$language]['success'] . "<br>";
                    } else {
                        $output .= sprintf($messages[$language]['error'], htmlspecialchars(json_encode($patchResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
                    }
                } else {
                    $output .= $messages[$language]['already_off'] . "<br>";
                }
            }
        }

        // Обработка IPv6
        if ($disableIPv6) {
            if ($ipv6Status === null) {
                $output .= sprintf($messages[$language]['not_found'], 'IPv6 (ipv6)') . "<br>";
            } else {
                $output .= sprintf($messages[$language]['ipv6_status'], htmlspecialchars($ipv6Status)) . "<br>";
                if ($ipv6Status !== 'off') {
                    $output .= $messages[$language]['ipv6_disabling'] . "<br>";
                    $patchData = [
                        'items' => [
                            [
                                'id' => 'ipv6',
                                'value' => 'off'
                            ]
                        ]
                    ];
                    $patchResult = makeApiRequest($url, $apiKey, $email, 'PATCH', $patchData);
                    if ($patchResult['success'] && $patchResult['code'] == 200 && $patchResult['response']['success']) {
                        $output .= $messages[$language]['ipv6_success'] . "<br>";
                    } else {
                        $output .= sprintf($messages[$language]['error'], htmlspecialchars(json_encode($patchResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
                    }
                } else {
                    $output .= $messages[$language]['ipv6_already_off'] . "<br>";
                }
            }
        }

        if (!$disableECH && !$disableIPv6) {
            $output .= $messages[$language]['empty_fields'] . "<br>";
        } elseif ($echStatus === null && $ipv6Status === null) {
            $output .= $messages[$language]['debug'] . "<br><pre>" . htmlspecialchars(json_encode($settings, JSON_PRETTY_PRINT)) . "</pre><br>";
        }
    } else {
        $output .= sprintf($messages[$language]['error'], htmlspecialchars($checkResult['message'] ?? json_encode($checkResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
    }
    
    return $output;
}

// Генерация CSRF-токена
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Обработка отправки формы
$result = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Проверка на бота через Cloudflare
    $botCheck = checkBotProtection($messages, $language);
    if ($botCheck) {
        $result = $botCheck . "<br>";
    } elseif (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $result = $messages[$language]['csrf_error'] . "<br>";
    } else {
        // Проверка наличия cf_clearance cookie
        if (isset($_COOKIE['cf_clearance'])) {
            if (isset($_POST['api_key'], $_POST['zone_id'], $_POST['email'])) {
                $apiKey = trim($_POST['api_key']);
                $zoneId = trim($_POST['zone_id']);
                $email = trim($_POST['email']);
                $disableECH = isset($_POST['disable_ech']) && $_POST['disable_ech'] === 'on';
                $disableIPv6 = isset($_POST['disable_ipv6']) && $_POST['disable_ipv6'] === 'on';
                
                if (!empty($apiKey) && !empty($zoneId) && !empty($email)) {
                    $result = processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language);
                } else {
                    $result = $messages[$language]['empty_fields'] . "<br>";
                }
            }
        } elseif (!isset($_POST['cf-turnstile-response']) || empty($_POST['cf-turnstile-response'])) {
            $result = $messages[$language]['turnstile_error'] . ": No token provided<br>";
        } else {
            // Проверка Turnstile токена
            $turnstileCheck = verifyTurnstile($_POST['cf-turnstile-response'], $turnstileSecretKey, $messages, $language);
            if ($turnstileCheck) {
                $result = $turnstileCheck . "<br>";
            } elseif (isset($_POST['api_key'], $_POST['zone_id'], $_POST['email'])) {
                $apiKey = trim($_POST['api_key']);
                $zoneId = trim($_POST['zone_id']);
                $email = trim($_POST['email']);
                $disableECH = isset($_POST['disable_ech']) && $_POST['disable_ech'] === 'on';
                $disableIPv6 = isset($_POST['disable_ipv6']) && $_POST['disable_ipv6'] === 'on';
                
                if (!empty($apiKey) && !empty($zoneId) && !empty($email)) {
                    $result = processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language);
                } else {
                    $result = $messages[$language]['empty_fields'] . "<br>";
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title><?php echo $messages[$language]['title']; ?></title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            box-sizing: border-box;
        }
        h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }
        input[type="text"],
        input[type="email"] {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        input[type="checkbox"] {
            margin-right: 0.5rem;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #0056b3;
        }
        .result {
            margin-top: 1.5rem;
            padding: 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }
        .error {
            color: red;
        }
        pre {
            background: #f4f4f4;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        .lang-switch {
            margin-bottom: 1.5rem;
            font-size: 1rem;
        }
        .lang-switch a {
            text-decoration: none;
            color: #007bff;
            margin-right: 0.5rem;
        }
        .lang-switch a:hover {
            text-decoration: underline;
        }

        /* Адаптивные стили для мобильных устройств */
        @media (max-width: 600px) {
            body {
                padding: 1rem;
            }
            h2 {
                font-size: 1.5rem;
            }
            label {
                font-size: 0.9rem;
            }
            input[type="text"],
            input[type="email"] {
                padding: 0.6rem;
                font-size: 0.9rem;
            }
            button {
                padding: 0.6rem;
                font-size: 0.9rem;
            }
            .result {
                padding: 0.75rem;
                font-size: 0.9rem;
            }
            pre {
                font-size: 0.8rem;
            }
            .lang-switch {
                font-size: 0.9rem;
            }
        }

        @media (max-width: 400px) {
            h2 {
                font-size: 1.2rem;
            }
            label {
                font-size: 0.85rem;
            }
            input[type="text"],
            input[type="email"] {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            button {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            .result {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            pre {
                font-size: 0.75rem;
            }
            .lang-switch {
                font-size: 0.85rem;
            }
        }
    </style>
</head>
<body>
    <div class="lang-switch">
        <a href="?lang=ru">Русский</a> | <a href="?lang=en">English</a>
    </div>
    
    <h2><?php echo $messages[$language]['title']; ?></h2>
    
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        
        <div class="form-group">
            <label for="api_key"><?php echo $messages[$language]['api_key_label']; ?></label>
            <input type="text" id="api_key" name="api_key" required pattern="[a-zA-Z0-9]{37}" title="<?php echo $language === 'ru' ? 'Global API Key должен содержать 37 символов (буквы и цифры)' : 'Global API Key must be 37 characters (letters and numbers)'; ?>">
        </div>
        
        <div class="form-group">
            <label for="zone_id"><?php echo $messages[$language]['zone_id_label']; ?></label>
            <input type="text" id="zone_id" name="zone_id" required pattern="[a-f0-9]{32}" title="<?php echo $language === 'ru' ? 'Zone ID должен содержать 32 символа (0-9, a-f)' : 'Zone ID must be 32 characters (0-9, a-f)'; ?>">
        </div>
        
        <div class="form-group">
            <label for="email"><?php echo $messages[$language]['email_label']; ?></label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" name="disable_ech" checked> <?php echo $messages[$language]['ech_checkbox']; ?>
            </label>
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" name="disable_ipv6"> <?php echo $messages[$language]['ipv6_checkbox']; ?>
            </label>
        </div>
        
        <div class="form-group">
            <?php if (!isset($_COOKIE['cf_clearance'])): ?>
                <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars($turnstileSiteKey); ?>"></div>
            <?php endif; ?>
        </div>
        
        <button type="submit"><?php echo $messages[$language]['submit_button']; ?></button>
    </form>
    
    <?php if ($result): ?>
        <div class="result <?php echo strpos($result, $messages[$language]['error']) !== false || strpos($result, $messages[$language]['bot_detected']) !== false || strpos($result, $messages[$language]['turnstile_error']) !== false ? 'error' : ''; ?>">
            <h3><?php echo $messages[$language]['result_title']; ?></h3>
            <?php echo $result; ?>
        </div>
    <?php endif; ?>
</body>
</html>
$turnstileSiteKey = '0x4AAAAAABAAuRuzCc1vnj7N';
$turnstileSecretKey = '0x4AAAAAABAAuc_3_lq9RET73OrSPqC3HV4';

// Проверка защиты от ботов через Cloudflare
function checkBotProtection($messages, $language) {
    $cfRay = isset($_SERVER['HTTP_CF_RAY']) ? $_SERVER['HTTP_CF_RAY'] : null;
    if (!$cfRay) {
        return $messages[$language]['bot_detected'];
    }
    return null;
}

// Проверка Turnstile токена
function verifyTurnstile($token, $secretKey, $messages, $language) {
    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    $data = [
        'secret' => $secretKey,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        curl_close($ch);
        return sprintf($messages[$language]['turnstile_error'], "cURL error: " . curl_error($ch));
    }
    curl_close($ch);

    $result = json_decode($response, true);
    if ($result === null || !isset($result['success'])) {
        return sprintf($messages[$language]['turnstile_error'], "Invalid response from Turnstile API");
    }
    if ($result['success'] === false) {
        return sprintf($messages[$language]['turnstile_error'], implode(', ', $result['error-codes'] ?? ['Unknown error']));
    }
    return null;
}

// Проверка формы и API-запросов
function processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language) {
    if (!preg_match('/^[a-zA-Z0-9]{37}$/', $apiKey)) {
        return sprintf($messages[$language]['error'], "Invalid Global API Key format.") . "<br>";
    }
    if (!preg_match('/^[a-f0-9]{32}$/', $zoneId)) {
        return sprintf($messages[$language]['error'], "Invalid Zone ID format.") . "<br>";
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return sprintf($messages[$language]['error'], "Invalid email format.") . "<br>";
    }

    $url = "https://api.cloudflare.com/client/v4/zones/{$zoneId}/settings";
    
    function makeApiRequest($url, $apiKey, $email, $method = 'GET', $data = null) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        
        $headers = [
            'X-Auth-Email: ' . trim($email),
            'X-Auth-Key: ' . trim($apiKey),
            'Content-Type: application/json'
        ];
        
        if ($method === 'PATCH' && $data) {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            return ['success' => false, 'message' => "cURL Error: $error"];
        }
        
        curl_close($ch);
        return ['success' => true, 'code' => $httpCode, 'response' => json_decode($response, true)];
    }

    $checkResult = makeApiRequest($url, $apiKey, $email);
    $output = '';

    if ($checkResult['success'] && $checkResult['code'] == 200 && $checkResult['response']['success']) {
        $settings = $checkResult['response']['result'];
        
        // Проверка ECH
        $echStatus = null;
        $ipv6Status = null;
        foreach ($settings as $setting) {
            if (isset($setting['id']) && $setting['id'] === 'ech') {
                $echStatus = $setting['value'];
            }
            if (isset($setting['id']) && $setting['id'] === 'ipv6') {
                $ipv6Status = $setting['value'];
            }
        }

        // Обработка ECH
        if ($disableECH) {
            if ($echStatus === null) {
                $output .= sprintf($messages[$language]['not_found'], 'ECH (ech)') . "<br>";
            } else {
                $output .= sprintf($messages[$language]['status'], htmlspecialchars($echStatus)) . "<br>";
                if ($echStatus !== 'off') {
                    $output .= $messages[$language]['disabling'] . "<br>";
                    $patchData = [
                        'items' => [
                            [
                                'id' => 'ech',
                                'value' => 'off'
                            ]
                        ]
                    ];
                    $patchResult = makeApiRequest($url, $apiKey, $email, 'PATCH', $patchData);
                    if ($patchResult['success'] && $patchResult['code'] == 200 && $patchResult['response']['success']) {
                        $output .= $messages[$language]['success'] . "<br>";
                    } else {
                        $output .= sprintf($messages[$language]['error'], htmlspecialchars(json_encode($patchResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
                    }
                } else {
                    $output .= $messages[$language]['already_off'] . "<br>";
                }
            }
        }

        // Обработка IPv6
        if ($disableIPv6) {
            if ($ipv6Status === null) {
                $output .= sprintf($messages[$language]['not_found'], 'IPv6 (ipv6)') . "<br>";
            } else {
                $output .= sprintf($messages[$language]['ipv6_status'], htmlspecialchars($ipv6Status)) . "<br>";
                if ($ipv6Status !== 'off') {
                    $output .= $messages[$language]['ipv6_disabling'] . "<br>";
                    $patchData = [
                        'items' => [
                            [
                                'id' => 'ipv6',
                                'value' => 'off'
                            ]
                        ]
                    ];
                    $patchResult = makeApiRequest($url, $apiKey, $email, 'PATCH', $patchData);
                    if ($patchResult['success'] && $patchResult['code'] == 200 && $patchResult['response']['success']) {
                        $output .= $messages[$language]['ipv6_success'] . "<br>";
                    } else {
                        $output .= sprintf($messages[$language]['error'], htmlspecialchars(json_encode($patchResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
                    }
                } else {
                    $output .= $messages[$language]['ipv6_already_off'] . "<br>";
                }
            }
        }

        if (!$disableECH && !$disableIPv6) {
            $output .= $messages[$language]['empty_fields'] . "<br>";
        } elseif ($echStatus === null && $ipv6Status === null) {
            $output .= $messages[$language]['debug'] . "<br><pre>" . htmlspecialchars(json_encode($settings, JSON_PRETTY_PRINT)) . "</pre><br>";
        }
    } else {
        $output .= sprintf($messages[$language]['error'], htmlspecialchars($checkResult['message'] ?? json_encode($checkResult['response']['errors'] ?? 'Unknown error'))) . "<br>";
    }
    
    return $output;
}

// Генерация CSRF-токена
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Обработка отправки формы
$result = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Проверка на бота через Cloudflare
    $botCheck = checkBotProtection($messages, $language);
    if ($botCheck) {
        $result = $botCheck . "<br>";
    } elseif (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $result = $messages[$language]['csrf_error'] . "<br>";
    } else {
        // Проверка наличия cf_clearance cookie
        if (isset($_COOKIE['cf_clearance'])) {
            if (isset($_POST['api_key'], $_POST['zone_id'], $_POST['email'])) {
                $apiKey = trim($_POST['api_key']);
                $zoneId = trim($_POST['zone_id']);
                $email = trim($_POST['email']);
                $disableECH = isset($_POST['disable_ech']) && $_POST['disable_ech'] === 'on';
                $disableIPv6 = isset($_POST['disable_ipv6']) && $_POST['disable_ipv6'] === 'on';
                
                if (!empty($apiKey) && !empty($zoneId) && !empty($email)) {
                    $result = processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language);
                } else {
                    $result = $messages[$language]['empty_fields'] . "<br>";
                }
            }
        } elseif (!isset($_POST['cf-turnstile-response']) || empty($_POST['cf-turnstile-response'])) {
            $result = $messages[$language]['turnstile_error'] . ": No token provided<br>";
        } else {
            // Проверка Turnstile токена
            $turnstileCheck = verifyTurnstile($_POST['cf-turnstile-response'], $turnstileSecretKey, $messages, $language);
            if ($turnstileCheck) {
                $result = $turnstileCheck . "<br>";
            } elseif (isset($_POST['api_key'], $_POST['zone_id'], $_POST['email'])) {
                $apiKey = trim($_POST['api_key']);
                $zoneId = trim($_POST['zone_id']);
                $email = trim($_POST['email']);
                $disableECH = isset($_POST['disable_ech']) && $_POST['disable_ech'] === 'on';
                $disableIPv6 = isset($_POST['disable_ipv6']) && $_POST['disable_ipv6'] === 'on';
                
                if (!empty($apiKey) && !empty($zoneId) && !empty($email)) {
                    $result = processForm($apiKey, $zoneId, $email, $disableECH, $disableIPv6, $messages, $language);
                } else {
                    $result = $messages[$language]['empty_fields'] . "<br>";
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title><?php echo $messages[$language]['title']; ?></title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            box-sizing: border-box;
        }
        h2 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }
        input[type="text"],
        input[type="email"] {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        input[type="checkbox"] {
            margin-right: 0.5rem;
        }
        button {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #0056b3;
        }
        .result {
            margin-top: 1.5rem;
            padding: 1rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }
        .error {
            color: red;
        }
        pre {
            background: #f4f4f4;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        .lang-switch {
            margin-bottom: 1.5rem;
            font-size: 1rem;
        }
        .lang-switch a {
            text-decoration: none;
            color: #007bff;
            margin-right: 0.5rem;
        }
        .lang-switch a:hover {
            text-decoration: underline;
        }

        /* Адаптивные стили для мобильных устройств */
        @media (max-width: 600px) {
            body {
                padding: 1rem;
            }
            h2 {
                font-size: 1.5rem;
            }
            label {
                font-size: 0.9rem;
            }
            input[type="text"],
            input[type="email"] {
                padding: 0.6rem;
                font-size: 0.9rem;
            }
            button {
                padding: 0.6rem;
                font-size: 0.9rem;
            }
            .result {
                padding: 0.75rem;
                font-size: 0.9rem;
            }
            pre {
                font-size: 0.8rem;
            }
            .lang-switch {
                font-size: 0.9rem;
            }
        }

        @media (max-width: 400px) {
            h2 {
                font-size: 1.2rem;
            }
            label {
                font-size: 0.85rem;
            }
            input[type="text"],
            input[type="email"] {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            button {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            .result {
                padding: 0.5rem;
                font-size: 0.85rem;
            }
            pre {
                font-size: 0.75rem;
            }
            .lang-switch {
                font-size: 0.85rem;
            }
        }
    </style>
</head>
<body>
    <div class="lang-switch">
        <a href="?lang=ru">Русский</a> | <a href="?lang=en">English</a>
    </div>
    
    <h2><?php echo $messages[$language]['title']; ?></h2>
    
    <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        
        <div class="form-group">
            <label for="api_key"><?php echo $messages[$language]['api_key_label']; ?></label>
            <input type="text" id="api_key" name="api_key" required pattern="[a-zA-Z0-9]{37}" title="<?php echo $language === 'ru' ? 'Global API Key должен содержать 37 символов (буквы и цифры)' : 'Global API Key must be 37 characters (letters and numbers)'; ?>">
        </div>
        
        <div class="form-group">
            <label for="zone_id"><?php echo $messages[$language]['zone_id_label']; ?></label>
            <input type="text" id="zone_id" name="zone_id" required pattern="[a-f0-9]{32}" title="<?php echo $language === 'ru' ? 'Zone ID должен содержать 32 символа (0-9, a-f)' : 'Zone ID must be 32 characters (0-9, a-f)'; ?>">
        </div>
        
        <div class="form-group">
            <label for="email"><?php echo $messages[$language]['email_label']; ?></label>
            <input type="email" id="email" name="email" required>
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" name="disable_ech" checked> <?php echo $messages[$language]['ech_checkbox']; ?>
            </label>
        </div>
        
        <div class="form-group">
            <label>
                <input type="checkbox" name="disable_ipv6"> <?php echo $messages[$language]['ipv6_checkbox']; ?>
            </label>
        </div>
        
        <div class="form-group">
            <?php if (!isset($_COOKIE['cf_clearance'])): ?>
                <div class="cf-turnstile" data-sitekey="<?php echo htmlspecialchars($turnstileSiteKey); ?>"></div>
            <?php endif; ?>
        </div>
        
        <button type="submit"><?php echo $messages[$language]['submit_button']; ?></button>
    </form>
    
    <?php if ($result): ?>
        <div class="result <?php echo strpos($result, $messages[$language]['error']) !== false || strpos($result, $messages[$language]['bot_detected']) !== false || strpos($result, $messages[$language]['turnstile_error']) !== false ? 'error' : ''; ?>">
            <h3><?php echo $messages[$language]['result_title']; ?></h3>
            <?php echo $result; ?>
        </div>
    <?php endif; ?>
</body>
</html>
