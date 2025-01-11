<?php

// includes/class-cookie-consent.php
class CookieConsent {
    public function __construct() {
        add_action('wp_footer', array($this, 'add_cookie_banner'));
        add_action('rest_api_init', array($this, 'register_cookie_consent_endpoint'));
    }

    public function add_cookie_banner() {
        if (isset($_COOKIE['cookie_consent'])) {
            return;
        }

        $this->render_cookie_banner();
    }

    private function render_cookie_banner() {
        include plugin_dir_path(__FILE__) . 'templates/cookie-banner.php';
    }

    public function register_cookie_consent_endpoint() {
        register_rest_route('security-plugin/v1', '/cookie-consent', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_cookie_consent'),
            'permission_callback' => '__return_true'
        ));
    }

    public function handle_cookie_consent($request) {
        $consent = $request->get_param('consent');
        if ($consent) {
            setcookie('cookie_consent', 'accepted', time() + (365 * 24 * 60 * 60), '/', '', true, true);
        }
        return new WP_REST_Response(array('status' => 'success'), 200);
    }
}
