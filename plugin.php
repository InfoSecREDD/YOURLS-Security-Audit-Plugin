<?php
/*
Plugin Name: Advanced Security Audit and URL Threat Detection Pro
Description: Robust threat detection and audit logging using multiple external APIs, caching, whitelisting, and an admin configuration/dashboard with Material Design.
Version: 3.1
Author: InfoSecREDD
Author URI: https://infosecredd.dev
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) {
    die();
}

// Ensure YOURLS_LOGDIR is defined; if not, use plugin directory as fallback
if( !defined('YOURLS_LOGDIR') ) {
    define('YOURLS_LOGDIR', dirname(__FILE__));
}

// CONFIGURATION: Default settings stored in YOURLS options
function asatdp_default_options() {
    $defaults = array(
        'google_api_key'     => '',
        'bing_api_key'       => '',
        'cache_expiration'   => 3600, // seconds
        'whitelisted_domains'=> '',
        'fail_open'          => true
    );
    foreach ($defaults as $key => $value) {
        if( yourls_get_option('asatdp_'.$key) === false ) {
            yourls_add_option('asatdp_'.$key, $value);
        }
    }
}
asatdp_default_options();

// Helper: Retrieve plugin option
function asatdp_get($key) {
    return yourls_get_option('asatdp_'.$key);
}

// Helper: Update plugin option
function asatdp_update($key, $value) {
    yourls_update_option('asatdp_'.$key, $value);
}

// HOOK: Pre-check URL before adding a new link
yourls_add_action('pre_add_new_link', 'asatdp_prevent_threat');
function asatdp_prevent_threat($args) {
    list($url, $keyword, $title) = $args;

    // Skip check if URL domain is whitelisted
    $whitelist = array_map('trim', explode(',', asatdp_get('whitelisted_domains')));
    $host = parse_url($url, PHP_URL_HOST);
    if($host && in_array($host, $whitelist)) {
        return $args;
    }
    
    $result = asatdp_check_url_threat($url);
    if ($result['threat_found']) {
        asatdp_log("Blocked URL: {$url}. Reason: " . $result['details']);
        yourls_die("Threat detected: " . $result['details']);
    }
    return $args;
}

// HOOK: Periodically recheck existing URLs for threats
yourls_add_action('load-index.php', 'asatdp_check_existing_urls');
function asatdp_check_existing_urls() {
    // Only run once per hour (or session) by checking a transient
    if (yourls_get_option('asatdp_last_recheck')) {
        $last_check = yourls_get_option('asatdp_last_recheck');
        // If last check was less than 1 hour ago, skip
        if (time() - $last_check < 3600) {
            return;
        }
    }
    
    // Update last check time
    yourls_update_option('asatdp_last_recheck', time());
    
    // Get a batch of URLs to check (limit to 10 to avoid overloading)
    global $ydb;
    $table = YOURLS_DB_TABLE_URL;
    $sql = "SELECT keyword, url FROM $table WHERE 1=1 LIMIT 10";
    $urls = $ydb->fetchObjects($sql);
    
    if (!$urls) {
        return;
    }
    
    foreach ($urls as $url_obj) {
        // Skip check if URL domain is whitelisted
        $whitelist = array_map('trim', explode(',', asatdp_get('whitelisted_domains')));
        $host = parse_url($url_obj->url, PHP_URL_HOST);
        if($host && in_array($host, $whitelist)) {
            continue;
        }
        
        // Check URL for threats
        $result = asatdp_check_url_threat($url_obj->url);
        if ($result['threat_found']) {
            asatdp_log("Disabling malicious URL: {$url_obj->url} (keyword: {$url_obj->keyword}). Reason: " . $result['details']);
            asatdp_disable_url($url_obj->keyword, $result['details']);
        }
    }
}

// Function to disable a URL by setting it to a warning page
function asatdp_disable_url($keyword, $reason) {
    global $ydb;
    $table = YOURLS_DB_TABLE_URL;
    
    // Create a safe redirect URL to a warning page
    $warning_url = yourls_admin_url('index.php') . '?page=asatdp_warning&keyword=' . $keyword . '&reason=' . urlencode($reason);
    
    // Update the URL in the database
    $sql = "UPDATE $table SET url = :warning_url, title = :title WHERE keyword = :keyword";
    $binds = array(
        'warning_url' => $warning_url,
        'title' => 'SECURITY THREAT: ' . substr($reason, 0, 50),
        'keyword' => $keyword
    );
    
    $update = $ydb->fetchAffected($sql, $binds);
    if ($update) {
        asatdp_log("URL disabled successfully: $keyword");
        return true;
    } else {
        asatdp_log("Error disabling URL: $keyword");
        return false;
    }
}

// Register a warning page for disabled URLs
yourls_register_plugin_page('asatdp_warning', 'Security Warning', 'asatdp_display_warning');
function asatdp_display_warning() {
    $keyword = isset($_GET['keyword']) ? $_GET['keyword'] : '';
    $reason = isset($_GET['reason']) ? $_GET['reason'] : 'Security threat detected';
    
    echo '<div style="text-align:center; padding:50px; background-color:#ffebee; max-width:800px; margin:0 auto; border-radius:4px;">';
    echo '<h2 style="color:#c62828;">⚠️ Security Warning</h2>';
    echo '<p>This shortened URL has been disabled because it was flagged as potentially malicious.</p>';
    echo '<p><strong>Reason:</strong> ' . htmlspecialchars($reason) . '</p>';
    echo '<p><strong>Short URL ID:</strong> ' . htmlspecialchars($keyword) . '</p>';
    echo '<p>If you believe this is a mistake, please contact the site administrator.</p>';
    echo '</div>';
}

// THREAT DETECTION: Robust check using caching and multiple APIs
function asatdp_check_url_threat($url) {
    $cache_key = 'asatdp_cache_' . md5($url);
    $cache = yourls_get_option($cache_key);
    if ($cache && (time() - $cache['timestamp'] < asatdp_get('cache_expiration'))) {
        return $cache['result'];
    }
    
    $result = array('threat_found' => false, 'details' => '');

    // Internal heuristic
    $suspicious_patterns = array('malware', 'phishing', 'virus', 'trojan');
    foreach ($suspicious_patterns as $pattern) {
        if (stripos($url, $pattern) !== false) {
            $result['threat_found'] = true;
            $result['details']   = "URL contains suspicious pattern: $pattern";
            asatdp_cache_result($cache_key, $result);
            return $result;
        }
    }
    
    // Google Safe Browsing Check
    $google_key = asatdp_get('google_api_key');
    if ($google_key) {
        $google_result = asatdp_google_safe_browsing($url, $google_key);
        if ($google_result['threat_found']) {
            $result = $google_result;
            asatdp_cache_result($cache_key, $result);
            return $result;
        }
    }
    
    // Bing URL Reputation API Check (placeholder example)
    $bing_key = asatdp_get('bing_api_key');
    if ($bing_key) {
        $bing_result = asatdp_bing_url_reputation($url, $bing_key);
        if ($bing_result['threat_found']) {
            $result = $bing_result;
            asatdp_cache_result($cache_key, $result);
            return $result;
        }
    }
    
    // No threats found
    asatdp_cache_result($cache_key, $result);
    return $result;
}

// Cache the result in YOURLS options
function asatdp_cache_result($cache_key, $result) {
    $data = array(
        'timestamp' => time(),
        'result'    => $result
    );
    yourls_update_option($cache_key, $data);
}

// Google Safe Browsing API check
function asatdp_google_safe_browsing($url, $api_key) {
    $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . $api_key;
    $payload = json_encode(array(
        "client" => array(
            "clientId"      => "yourls-plugin",
            "clientVersion" => "3.1"
        ),
        "threatInfo" => array(
            "threatTypes"      => ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes"    => ["ANY_PLATFORM"],
            "threatEntryTypes" => ["URL"],
            "threatEntries"    => array(array("url" => $url))
        )
    ));
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $endpoint);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    $api_response = curl_exec($ch);
    $http_code    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $result = array('threat_found' => false, 'details' => '');
    if ($http_code == 200 && $api_response) {
        $data = json_decode($api_response, true);
        if (!empty($data['matches'])) {
            $threats = array();
            foreach ($data['matches'] as $match) {
                $threats[] = $match['threatType'];
            }
            $result['threat_found'] = true;
            $result['details']     = "Google Safe Browsing: " . implode(', ', $threats);
        }
    } else {
        asatdp_log("Google API error for URL: {$url}. HTTP Code: {$http_code}");
    }
    return $result;
}

// Bing URL Reputation API check (placeholder implementation)
function asatdp_bing_url_reputation($url, $api_key) {
    // Placeholder: In a real implementation, integrate with Bing's API.
    $result = array('threat_found' => false, 'details' => '');
    return $result;
}

// HOOK: Log audit details after URL creation and update
yourls_add_action('add_new_link', 'asatdp_log_new_link');
yourls_add_action('edit_link', 'asatdp_log_new_link');
function asatdp_log_new_link($args) {
    list($url, $keyword, $title, $ip, $timestamp, $clicks) = $args;
    $log_entry = sprintf("URL: %s | Keyword: %s | Title: %s | IP: %s | Time: %s | Clicks: %d", $url, $keyword, $title, $ip, $timestamp, $clicks);
    asatdp_log($log_entry);
}

// LOGGING FUNCTION: Append log entry to audit log file
if( !defined( 'ASATDP_LOG_FILE' ) ) {
    define('ASATDP_LOG_FILE', YOURLS_LOGDIR . '/asatdp_audit.log');
}
function asatdp_log($entry) {
    $date = date("Y-m-d H:i:s");
    $formatted = "[{$date}] {$entry}\n";
    error_log($formatted, 3, ASATDP_LOG_FILE);
}

// ADMIN DASHBOARD & CONFIGURATION with Material Design
yourls_register_plugin_page('asatdp_dashboard', 'Security Audit Dashboard', 'asatdp_render_dashboard');
function asatdp_render_dashboard() {
    // Handle form submission for updating settings
    if (isset($_POST['asatdp_update'])) {
        asatdp_update('google_api_key', trim($_POST['google_api_key']));
        asatdp_update('bing_api_key', trim($_POST['bing_api_key']));
        asatdp_update('cache_expiration', intval($_POST['cache_expiration']));
        asatdp_update('whitelisted_domains', trim($_POST['whitelisted_domains']));
        asatdp_update('fail_open', isset($_POST['fail_open']) ? true : false);
        echo "<div class='card-panel green lighten-2 white-text'>Settings updated.</div>";
    }
    
    $google_api_key      = asatdp_get('google_api_key');
    $bing_api_key        = asatdp_get('bing_api_key');
    $cache_expiration    = asatdp_get('cache_expiration');
    $whitelisted_domains = asatdp_get('whitelisted_domains');
    $fail_open           = asatdp_get('fail_open');
    $logContent          = file_exists(ASATDP_LOG_FILE) ? file_get_contents(ASATDP_LOG_FILE) : "No audit logs found.";
    ?>
    <!-- Include Materialize CSS and icons in the header -->
    <style>
        #main { width: 100%; }
        pre { background: #eceff1; padding: 15px; border-radius: 4px; }
        .card { margin: 20px 0; background: white; border-radius: 4px; box-shadow: 0 2px 2px 0 rgba(0,0,0,0.14), 0 3px 1px -2px rgba(0,0,0,0.12), 0 1px 5px 0 rgba(0,0,0,0.2); }
        .card-content { padding: 24px; }
        .card-title { font-size: 24px; font-weight: 300; margin-bottom: 20px; }
        .input-field { margin: 15px 0; }
        .btn { background-color: #26a69a; color: white; border: none; padding: 10px 15px; border-radius: 2px; cursor: pointer; text-transform: uppercase; }
        .btn:hover { background-color: #2bbbad; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="number"] { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 2px; }
        .card-panel { padding: 15px; margin: 15px 0; border-radius: 2px; }
        .green { background-color: #4CAF50; }
        .white-text { color: white; }
    </style>
    
    <h2>Security Audit & Configuration Dashboard</h2>
    
    <div class="card">
        <div class="card-content">
            <span class="card-title">Settings</span>
            <form method="post">
                <div class="input-field">
                    <label for="google_api_key">Google API Key</label>
                    <input id="google_api_key" type="text" name="google_api_key" value="<?php echo htmlspecialchars($google_api_key); ?>">
                </div>
                <div class="input-field">
                    <label for="bing_api_key">Bing API Key</label>
                    <input id="bing_api_key" type="text" name="bing_api_key" value="<?php echo htmlspecialchars($bing_api_key); ?>">
                </div>
                <div class="input-field">
                    <label for="cache_expiration">Cache Expiration (seconds)</label>
                    <input id="cache_expiration" type="number" name="cache_expiration" value="<?php echo intval($cache_expiration); ?>">
                </div>
                <div class="input-field">
                    <label for="whitelisted_domains">Whitelisted Domains (comma separated)</label>
                    <input id="whitelisted_domains" type="text" name="whitelisted_domains" value="<?php echo htmlspecialchars($whitelisted_domains); ?>">
                </div>
                <p>
                    <label>
                        <input type="checkbox" name="fail_open" <?php echo $fail_open ? 'checked' : ''; ?>/>
                        <span>Fail open on API error</span>
                    </label>
                </p>
                <div class="input-field">
                    <input type="submit" name="asatdp_update" value="Update Settings" class="btn">
                </div>
            </form>
        </div>
    </div>
    
    <div class="card">
        <div class="card-content">
            <span class="card-title">Audit Logs</span>
            <pre><?php echo htmlspecialchars($logContent); ?></pre>
        </div>
    </div>
    <?php
}
?>
