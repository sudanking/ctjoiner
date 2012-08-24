<?php

/*
 *   Document   : fun.php
 *   Created on : Aug 21, 2012, 3:16 AM
 *   Author     : Sudanking
 *   Description:
 *       Class's and many functions file.
 */

// Many functions

function get_url_contents($url) {
    $crl = curl_init();
    $timeout = 5;
    curl_setopt($crl, CURLOPT_URL, $url);
    curl_setopt($crl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($crl, CURLOPT_CONNECTTIMEOUT, $timeout);
    $ret = curl_exec($crl);
    curl_close($crl);
    return $ret;
}

function decryptTracker($cipher, $key) {

    $tracker_key = $key;
    $cipher_tracker = $cipher;

    $cipher = new ircBFish();
    $plain_tracker = $cipher->decrypt($cipher_tracker, $tracker_key);

    unset($cipher);
    return $plain_tracker;
}

function checkNodes($nodes) {
    if ($nodes->length == 0) {
        return false;
    } else {
        return true;
    }
}

function ecryptTracker($plain, $key) {

    $tracker_key = $key;
    $plain_tracker = $plain;

    $cipher = new ircBFish();
    $enc_tracker = $cipher->encrypt($plain_tracker, $tracker_key);

    unset($cipher);
    return $enc_tracker;
}

function specHTML($str) {
    // Special html chars

    $str = str_replace(" ", "&nbsp;", $str);
    $str = str_replace("<", "&lt;", $str);
    $str = str_replace(">", "&gt;", $str);

    return $str;
}

function strtoJava($str) {
    $ret = "";
    $special = array("\"", "'", chr(92));

    for ($i = 0; $i < strlen($str); $i++) {

        $c = substr($str, $i, 1);

        if ((ord($c) >= 32) && (ord($c) <= 126) && (!in_array($c, $special)))
            $ret .= $c;
        else
            $ret .= "\" + String.fromCharCode(" . ord($c) . ") + \"";
    }
    return $ret;
}

// Blowfish encryption support

class ircBFish {

    // Conversion table
    var $B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    function bytetoB64($ec) {
        $dc = "";

        $k = -1;
        while ($k < (strlen($ec) - 1)) {

            $k++;
            $left = (ord($ec{$k}) << 24);
            $k++;
            $left += ( ord($ec{$k}) << 16);
            $k++;
            $left += ( ord($ec{$k}) << 8);
            $k++;
            $left += ord($ec{$k});

            $k++;
            $right = (ord($ec{$k}) << 24);
            $k++;
            $right += ( ord($ec{$k}) << 16);
            $k++;
            $right += ( ord($ec{$k}) << 8);
            $k++;
            $right += ord($ec{$k});

            for ($i = 0; $i < 6; $i++) {
                $dc .= $this->B64{$right & 0x3F};
                $right = $right >> 6;
            }

            for ($i = 0; $i < 6; $i++) {
                $dc .= $this->B64{$left & 0x3F};
                $left = $left >> 6;
            }
        }

        return $dc;
    }

    function B64tobyte($ec) {
        $dc = "";

        $k = -1;
        while ($k < (strlen($ec) - 1)) {

            $right = 0;
            $left = 0;

            for ($i = 0; $i < 6; $i++) {
                $k++;
                $right |= @ strpos($this->B64, $ec{$k}) << ($i * 6);
            }

            for ($i = 0; $i < 6; $i++) {
                $k++;
                $left |= @ strpos($this->B64, $ec{$k}) << ($i * 6);
            }

            for ($i = 0; $i < 4; $i++)
                $dc .= chr(($left & (0xFF << ((3 - $i) * 8))) >> ((3 - $i) * 8));

            for ($i = 0; $i < 4; $i++)
                $dc .= chr(($right & (0xFF << ((3 - $i) * 8))) >> ((3 - $i) * 8));
        }

        return $dc;
    }

    function encrypt($text, $key) {
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, "", MCRYPT_MODE_ECB, "");
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_RANDOM);

        $text .= str_repeat(chr(0), 8 - (strlen($text) % 8));

        mcrypt_generic_init($td, $key, $iv);

        $ec = mcrypt_generic($td, $text);

        mcrypt_module_close($td);

        return $this->bytetoB64($ec);
    }

    function decrypt($text, $key) {
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, "", MCRYPT_MODE_ECB, "");
//        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_RANDOM);
        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_URANDOM);

        mcrypt_generic_init($td, $key, $iv);

        $tmp = mdecrypt_generic($td, $this->B64tobyte($text));
        $tmp = str_replace(chr(0), "", $tmp);

        mcrypt_module_close($td);

        return $tmp;
    }

}

function checkDuplication($trackerArray, $tracker) {

    foreach ($trackerArray as $trackerList) {

        if (in_array($tracker, $trackerList, true)) {
//        if (array_search($tracker, $trackerList, true)) {
            $foundDup[] = "true";
        }
    }

    if (!empty($foundDup)) {
        return true;
    } else {
        return false;
    }
}

function getReqIp() {

    //FIND THE VISITORS IP      
    if (getenv("HTTP_CLIENT_IP") && strcasecmp(getenv("HTTP_CLIENT_IP"), "unknown")) {
        $rip = getenv("HTTP_CLIENT_IP");
    } else if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown")) {
        $rip = getenv("HTTP_X_FORWARDED_FOR");
    } else if (getenv("REMOTE_ADDR") && strcasecmp(getenv("REMOTE_ADDR"), "unknown")) {
        $rip = getenv("REMOTE_ADDR");
    } else if (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], "unknown")) {
        $rip = $_SERVER['REMOTE_ADDR'];
    } else {
        $rip = "unknown";
    }

//DISPLAY THE VISITORS IP
//    echo "Your IP is $rip";
    return $rip;
}