<?php

/*
 * Document   : cluster.php
 *   Created on : Aug 21, 2012, 3:16 AM
 *   Author     : Sudanking
 *   Description:
 *          Join multible cache trackers (encrypted or plain text) in one encrypted tracker
 *          All configuration must be set in setting.xml
 */

include_once 'class.php';
include_once 'fun.php';

$des = "";
$url = "";
$key = "";
$blackList = array();
$foundDup = array();
$trackerArray = array();
$tempTrackerArray = array();
$debug = false;
$enabled = true;
$myTrackerKey = "";
$tracker = "";
$trackerOutput = "";
$requestedIP = getReqIp();


$dom = new MyDOMDocument();
$dom->load('settings.xml');

//to explore dom as array
//print_r($dom->toArray());
//Read tracker key value from settings.xml
if (checkNodes($dom->getElementsByTagName('my_tracker_key'))) {
    $myTrackerKey = $dom->getElementsByTagName('my_tracker_key')->item(0)->nodeValue;
}

//Read debug value from settings.xml
if (checkNodes($dom->getElementsByTagName('debug'))) {
    $debugValue = $dom->getElementsByTagName('debug')->item(0)->getAttribute('enabled');
    if ($debugValue == 'true') {
        $debug = true;
    }
}

//
// Build black list host array
if (checkNodes($dom->getElementsByTagName('blackList'))) {
    $blackListNode = $dom->getElementsByTagName('blackList')->item(0)->getElementsByTagName('host');
    foreach ($blackListNode as $host) {
        if ($host->getAttribute('enabled') == "false") {
            continue;
        } else {
            $blackList[] = $host->nodeValue;
        }
    }
}

$node = $dom->getElementsByTagName('tracker');

$tracker = '';
$trackerCount = 0;

foreach ($node as $elem) {
    $trackerCount++;

    $enabled = $elem->getAttribute('enabled');
    if ($enabled == "false")
        continue;

    if (checkNodes($elem->getElementsByTagName('tracker_url'))) {
        $url = $elem->getElementsByTagName('tracker_url')->item(0)->nodeValue;
        $parse = parse_url(trim($url), PHP_URL_HOST);
        $host = isset($parse) ? str_ireplace('www.', '', $parse) : '';
        if (gethostbyname($host) == $requestedIP)
            continue;
    }

    if (checkNodes($elem->getElementsByTagName('tracker_des'))) {
        $des = $elem->getElementsByTagName('tracker_des')->item(0)->nodeValue;
    } else {
        $des = "Tracker " . $trackerCount;
    }

    if (checkNodes($elem->getElementsByTagName('tracker_key'))) {
        $key = $elem->getElementsByTagName('tracker_key')->item(0)->nodeValue;
    }

    if (empty($key)) {
        if ($file_content = @file_get_contents($url)) {
            unset($tempTrackerArray);
            $plainTracker = trim($file_content);
            $tempTrackerArray = array_unique(preg_split("/[\s,]+/", $plainTracker));

            foreach ($tempTrackerArray as $tracker) {
                // Check if host is blacklisted
                if (in_array($tracker, $blackList)) {
                    continue;
                } else {
                    if (!checkDuplication($trackerArray, $tracker)) {
                        $trackerArray[$des][] = $tracker;
                    }
                }
            }
        } else {
            $trackerArray[$des][] = "## Error get tracker info" . "\n";
        }
    } else {
        if ($file_content = @file_get_contents($url)) {
            unset($tempTrackerArray);
            $encTracker = trim($file_content);
            $plainTracker = decryptTracker($encTracker, $key);
            $tempTrackerArray = array_unique(preg_split("/[\s,]+/", $plainTracker));

            foreach ($tempTrackerArray as $tracker) {

                // Check if host is blacklisted
                if (in_array($tracker, $blackList)) {
                    continue;
                } else {
                    if (!checkDuplication($trackerArray, $tracker)) {
                        $trackerArray[$des][] = $tracker;
                    }
                }
            }
        } else {
            $trackerArray[$des][] = "## Error get tracker info" . "\n";
        }
    }
}

// Create output file
foreach ($trackerArray as $arrayName => $array) {
    $trackerOutput .= "### [ " . $arrayName . " ] ############################# \n";
    foreach ($array as $value) {
        $trackerOutput .= $value . "\n";
    }
}


if ($debug) {
    print($trackerOutput);
} else {
    if ($myTrackerKey) {
        $encTracker = ecryptTracker($trackerOutput, $myTrackerKey);
        print $encTracker;
    } else {
        echo "Error: there is no KEY defined in settings.xml to enc you tracker!!! ";
    }
}
