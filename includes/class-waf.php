<?php

class SecurityWAF {
    private $blocked_ips = array();
    private $request_limit = 100;
    private $blacklist_threshold = 5;

    public function __construct() {
        if (get_option('security_enable_waf', true)) {
            $this->init();
        }
    }

    private function init() {
        add_action('init', array($this, 'waf_check'), 1);
        add_action('admin_init', array($this, 'schedule_cleanup'));
    }

    public function waf_check() {
        $ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($ip)) {
            $this->block_request('IP Blocked');
        }

        if ($this->is_rate_limited($ip)) {
            $this->log_violation($ip, 'Rate Limit Exceeded');
            $this->block_request('Rate Limit Exceeded');
        }

        $this->check_attack_patterns($ip);
    }

    private function check_attack_patterns($ip) {
        // Check for SQL injection
        if ($this->detect_sql_injection()) {
            $this->log_violation($ip, 'SQL Injection Attempt');
            $this->block_request('Invalid Request');
        }

        // Check for XSS
        if ($this->detect_xss()) {
            $this->log_violation($ip, 'XSS Attempt');
            $this->block_request('Invalid Request');
        }

        // Check for file inclusion
        if ($this->detect_file_inclusion()) {
            $this->log_violation($ip, 'File Inclusion Attempt');
            $this->block_request('Invalid Request');
        }
    }

    private function detect_sql_injection() {
        $patterns = array(
            '/union\s+select/i',
            '/exec\s*\(/i',
            '/INFORMATION_SCHEMA/i',
            '/into\s+outfile/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function detect_xss() {
        $patterns = array(
            '/<script.*?>.*?<\/script>/is',
            '/javascript:/i',
            '/onload=/i',
            '/onerror=/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function detect_file_inclusion() {
        $patterns = array(
            '/\.\.\//i',
            '/etc\/passwd/i',
            '/include\s*\(/i',
            '/require\s*\(/i'
        );
        
        return $this->check_patterns($patterns);
    }

    private function check_patterns($patterns) {
        $input = array(
            $_SERVER['REQUEST_URI'],
            file_get_contents('php://input'),
            implode(' ', $_GET),
            implode(' ', $_POST),
            implode(' ', $_COOKIE)
        );
        
        foreach ($patterns as $pattern) {
            foreach ($input as $value) {
                if (preg_match($pattern, $value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function is_rate_limited($ip) {
        $requests = get_transient('waf_requests_' . $ip);
        if ($requests === false) {
            set_transient('waf_requests_' . $ip, 1, 60);
            return false;
        }
        
        if ($requests >= $this->request_limit) {
            return true;
        }
        
        set_transient('waf_requests_' . $ip, $requests + 1, 60);
        return false;
    }

    private function log_violation($ip, $type) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'waf_logs';
        
        $wpdb->insert(
            $table_name,
            array(
                'ip_address' => $ip,
                'violation_type' => $type,
                'request_uri' => $_SERVER['REQUEST_URI'],
                'timestamp' => current_time('mysql')
            )
        );

        // Check for blacklist threshold
        $violations = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name WHERE ip_address = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            $ip
        ));

        if ($violations >= $this->blacklist_threshold) {
            $this->blacklist_ip($ip);
        }
    }

    private function blacklist_ip($ip) {
        $blocked_ips = get_option('waf_blocked_ips', array());
        if (!in_array($ip, $blocked_ips)) {
            $blocked_ips[] = $ip;
            update_option('waf_blocked_ips', $blocked_ips);
        }
    }

    private function is_ip_blocked($ip) {
        $blocked_ips = get_option('waf_blocked_ips', array());
        return in_array($ip, $blocked_ips);
    }

    private function block_request($reason) {
        status_header(403);
        die('Access Denied: ' . $reason);
    }

    private function get_client_ip() {
        return isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? 
               $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
    }

    public function schedule_cleanup() {
        if (!wp_next_scheduled('waf_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'waf_cleanup_logs');
        }
    }

    public function cleanup_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'waf_logs';
        
        // Remove logs older than 30 days
        $wpdb->query(
            "DELETE FROM $table_name WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
    }
}