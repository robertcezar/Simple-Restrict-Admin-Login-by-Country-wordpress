<?php
/*
Plugin Name: Restrict Admin Login by Country
Description: Blocks admin and shop_manager logins from countries other than RO using ipinfo.io.
Version: 1.0
Author: GRC
*/

add_filter('authenticate', 'restrict_admin_login_by_country', 21, 3);

function restrict_admin_login_by_country($user, $username, $password) {
    if (is_wp_login()) {
        $user_obj = get_user_by('login', $username);
        if (!$user_obj) return $user;

        $restricted_roles = ['administrator', 'shop_manager'];
        $user_roles = $user_obj->roles;
        $ip = $_SERVER['REMOTE_ADDR'];

        foreach ($user_roles as $role) {
            if (in_array($role, $restricted_roles)) {
                $response = wp_remote_get("https://ipinfo.io/{$ip}/country");
                if (is_wp_error($response)) {
                    return new WP_Error('ipinfo_error', __('GeoIP lookup failed. Try again.'));
                }

                $country = trim(wp_remote_retrieve_body($response));

                if ($country !== 'RO') {
                    return new WP_Error('access_denied', __('Login restricted: Not allowed from your country.'));
                }
                break;
            }
        }
    }
    return $user;
}

function is_wp_login() {
    return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-signup.php']);
}
