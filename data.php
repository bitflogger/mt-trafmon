<?php
header('Content-Type: application/json');

$rrdFile = '/var/www/html/traffic.rrd';

if (!file_exists($rrdFile)) {
    echo json_encode(['error' => 'RRD file not generated yet.']);
    exit;
}

// Fetch the last 5 minutes (300 seconds) of data from RRD
$endTime = time();
$startTime = $endTime - 300;

// Execute system rrdtool fetch to guarantee compatibility without complex extensions
$command = "rrdtool fetch $rrdFile AVERAGE --start $startTime --end $endTime";
exec($command, $output);

$timestamps = [];
$rxData = [];
$txData = [];

// Parse RRD output lines
// Skip the first two header rows
for ($i = 2; $i < count($output); $i++) {
    $line = trim($output[$i]);
    if (empty($line)) continue;
    
    // RRD outputs as "timestamp: rx_val tx_val"
    $parts = preg_split('/:\s+|\s+/', $line);
    
    if (count($parts) >= 3) {
        $ts = (int)$parts[0];
        $rx = $parts[1];
        $tx = $parts[2];
        
        // Convert "nan" strings to 0 for JavaScript parsing compatibility
        $rx = (is_numeric($rx)) ? round((float)$rx / 1000000, 2) : 0; // Convert to Mbps
        $tx = (is_numeric($tx)) ? round((float)$tx / 1000000, 2) : 0; // Convert to Mbps
        
        $timestamps[] = date('H:i:s', $ts);
        $rxData[] = $rx;
        $txData[] = $tx;
    }
}

echo json_encode([
    'labels' => $timestamps,
    'rx' => $rxData,
    'tx' => $txData
]);
?>

