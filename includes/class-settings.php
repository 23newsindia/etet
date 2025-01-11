<?php 

// includes/class-settings.php
class SecuritySettings {
    public function add_admin_menu() {
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings',
            array($this, 'render_settings_page'),
            'dashicons-shield'
        );
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['save_settings'])) {
            $this->save_settings();
        }

        include plugin_dir_path(__FILE__) . 'templates/settings-page.php';
    }

    public function register_settings() {
        register_setting('security_settings', 'security_enable_waf');
        register_setting('security_settings', 'security_enable_xss');
        // ... (register other settings)
    }

    private function save_settings() {
        if (!isset($_POST['security_nonce']) || 
            !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        $this->update_security_options();
    }

    private function update_security_options() {
      
          if (!current_user_can('manage_options')) {
        return;
    }

        // Verify nonce
    if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
        wp_die('Security check failed');
    }

    // Add XSS protection toggle
     update_option('security_enable_xss', isset($_POST['enable_xss']));

        $excluded_paths = isset($_POST['excluded_paths']) ? sanitize_textarea_field($_POST['excluded_paths']) : '';
        $blocked_patterns = isset($_POST['blocked_patterns']) ? sanitize_textarea_field($_POST['blocked_patterns']) : '';
        $excluded_php_paths = isset($_POST['excluded_php_paths']) ? sanitize_textarea_field($_POST['excluded_php_paths']) : '';
        
         update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        
        update_option('security_excluded_paths', $excluded_paths);
        update_option('security_blocked_patterns', $blocked_patterns);
        update_option('security_excluded_php_paths', $excluded_php_paths);
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
    }
}
