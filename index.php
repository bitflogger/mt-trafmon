<?php
declare(strict_types=1);

$RRD_FILE = '/var/www/koutstaal.com/trafmon/traffic.rrd';
$TITLE = 'Internet Traffic';

function get_param(string $name, string $default): string {
    return isset($_GET[$name]) ? trim((string)$_GET[$name]) : $default;
}

function int_param(string $name, int $default, int $min, int $max): int {
    $v = filter_input(INPUT_GET, $name, FILTER_VALIDATE_INT);
    if ($v === false || $v === null) return $default;
    return max($min, min($max, $v));
}

function bool_param(string $name): bool {
    return isset($_GET[$name]) && $_GET[$name] === '1';
}

function valid_epoch_or_null(string $name): ?int {
    if (!isset($_GET[$name])) return null;
    if (!preg_match('/^\d+$/', (string)$_GET[$name])) return null;

    $v = (int)$_GET[$name];

    if ($v < 946684800 || $v > 4102444800) return null;

    return $v;
}

function range_to_seconds(string $range): int {
    return match ($range) {
        '5m'  => 300,
        '15m' => 900,
        '1h'  => 3600,
        '6h'  => 21600,
        '24h' => 86400,
        '7d'  => 604800,
        '30d' => 2592000,
        '1y'  => 31557600,
        '5y'  => 157788000,
        default => 3600,
    };
}

function safe_style(string $style): string {
    return in_array($style, ['area', 'line', 'mirror'], true) ? $style : 'area';
}

function human_duration(int $seconds): string {
    if ($seconds < 60) {
        return $seconds . ' second' . ($seconds === 1 ? '' : 's');
    }

    if ($seconds < 3600) {
        return round($seconds / 60, 1) . ' minutes';
    }

    if ($seconds < 86400) {
        return round($seconds / 3600, 1) . ' hours';
    }

    return round($seconds / 86400, 1) . ' days';
}

function resolution_for_window(int $start, int $end, int $width): array {
    $span = max(1, $end - $start);

    /*
     * Archive availability based on your selected RRD layout:
     * 1s data:  1 year
     * 10s data: 5 years
     * 5m data:  beyond that
     */
    if ($span <= 31557600) {
        $archiveStep = 1;
        $archiveLabel = '1 second RRD archive';
    } elseif ($span <= 157788000) {
        $archiveStep = 10;
        $archiveLabel = '10 second RRD archive';
    } else {
        $archiveStep = 300;
        $archiveLabel = '5 minute RRD archive';
    }

    /*
     * Display resolution: the graph cannot show more horizontal time samples
     * than the graph width in pixels.
     */
    $pixelStep = (int)ceil($span / max(1, $width));

    /*
     * Effective resolution is the coarser of:
     * - archive precision
     * - display/pixel precision
     */
    $effectiveStep = max($archiveStep, $pixelStep);

    return [
        $effectiveStep,
        human_duration($effectiveStep),
        $archiveStep,
        $archiveLabel,
        $pixelStep,
        human_duration($pixelStep),
    ];
}

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES);
}

$range = get_param('range', '1h');
$width = int_param('width', 1200, 300, 4000);
$height = int_param('height', 420, 150, 2000);
$style = safe_style(get_param('style', 'area'));
$log = bool_param('log');
$smooth = bool_param('smooth');

$startEpoch = valid_epoch_or_null('start');
$endEpoch = valid_epoch_or_null('end');

if ($startEpoch !== null && $endEpoch !== null && $endEpoch > $startEpoch) {
    $graphStart = $startEpoch;
    $graphEnd = $endEpoch;
    $range = 'custom';
} else {
    $seconds = range_to_seconds($range);
    $graphEnd = time();
    $graphStart = $graphEnd - $seconds;
}

if ($log && $style === 'mirror') {
    $style = 'area';
}

[
    $resolutionSeconds,
    $resolutionLabel,
    $archiveStep,
    $archiveLabel,
    $pixelStep,
    $pixelLabel
] = resolution_for_window($graphStart, $graphEnd, $width);

if (isset($_GET['graph'])) {
    if (!is_file($RRD_FILE)) {
        http_response_code(500);
        header('Content-Type: text/plain');
        exit("RRD file not found: {$RRD_FILE}\n");
    }

    $tmp = tempnam(sys_get_temp_dir(), 'rrdgraph_');
    if ($tmp === false) {
        http_response_code(500);
        header('Content-Type: text/plain');
        exit("Could not create temp file\n");
    }

    $args = [
        'rrdtool', 'graph', $tmp,
        '--start', (string)$graphStart,
        '--end', (string)$graphEnd,
        '--step', (string)$resolutionSeconds,
        '--width', (string)$width,
        '--height', (string)$height,
        '--title', $TITLE,
        '--vertical-label', 'bit/s',
        '--slope-mode',
        '--alt-autoscale-max',
        '--imgformat', 'PNG',
        '--font', 'TITLE:12:',
        '--font', 'AXIS:9:',
        '--font', 'LEGEND:9:',
        '--font', 'UNIT:9:',
    ];

    if ($log) {
        $args[] = '--logarithmic';
        $args[] = '--lower-limit';
        $args[] = '1';
    } elseif ($style !== 'mirror') {
        $args[] = '--lower-limit';
        $args[] = '0';
    }

    $args[] = "DEF:rx_raw={$RRD_FILE}:rx:AVERAGE";
    $args[] = "DEF:tx_raw={$RRD_FILE}:tx:AVERAGE";

    if ($smooth) {
        $args[] = "CDEF:rx=rx_raw,60,TREND";
        $args[] = "CDEF:tx=tx_raw,60,TREND";
    } else {
        $args[] = "CDEF:rx=rx_raw";
        $args[] = "CDEF:tx=tx_raw";
    }

    if ($log) {
        $args[] = "CDEF:rxplot=rx,1,MAX";
        $args[] = "CDEF:txsafe=tx,1,MAX";
    } else {
        $args[] = "CDEF:rxplot=rx";
        $args[] = "CDEF:txsafe=tx";
    }

    if ($style === 'mirror' && !$log) {
        $args[] = "CDEF:txplot=txsafe,-1,*";
    } else {
        $args[] = "CDEF:txplot=txsafe";
    }

    if ($style === 'line') {
        $args[] = "LINE2:rxplot#00cc66:RX inbound";
        $args[] = "LINE2:txplot#3399ff:TX outbound";
    } elseif ($style === 'mirror') {
        $args[] = "AREA:rxplot#99e6bb:RX inbound";
        $args[] = "LINE1:rxplot#00aa55";
        $args[] = "AREA:txplot#b3d9ff:TX outbound";
        $args[] = "LINE1:txplot#2277cc";
        $args[] = "HRULE:0#666666";
    } else {
        $args[] = "AREA:rxplot#99e6bb:RX inbound";
        $args[] = "LINE1:rxplot#00aa55";
        $args[] = "AREA:txplot#b3d9ff:TX outbound";
        $args[] = "LINE1:txplot#2277cc";
    }

    $args[] = "GPRINT:rx:LAST:RX last\\: %6.2lf %Sbit/s";
    $args[] = "GPRINT:rx:AVERAGE:avg\\: %6.2lf %Sbit/s";
    $args[] = "GPRINT:rx:MAX:max\\: %6.2lf %Sbit/s\\n";

    $args[] = "GPRINT:tx:LAST:TX last\\: %6.2lf %Sbit/s";
    $args[] = "GPRINT:tx:AVERAGE:avg\\: %6.2lf %Sbit/s";
    $args[] = "GPRINT:tx:MAX:max\\: %6.2lf %Sbit/s\\n";

    $cmd = '';
    foreach ($args as $arg) {
        $cmd .= escapeshellarg($arg) . ' ';
    }
    $cmd .= '2>&1';

    exec($cmd, $output, $rc);

    if ($rc !== 0 || !is_file($tmp) || filesize($tmp) === 0) {
        http_response_code(500);
        header('Content-Type: text/plain');
        echo "rrdtool graph failed\n\n";
        echo implode("\n", $output);
        @unlink($tmp);
        exit;
    }

    header('Content-Type: image/png');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    readfile($tmp);
    @unlink($tmp);
    exit;
}

$query = http_build_query([
    'graph' => 1,
    'start' => $graphStart,
    'end' => $graphEnd,
    'width' => $width,
    'height' => $height,
    'style' => $style,
    'log' => $log ? 1 : 0,
    'smooth' => $smooth ? 1 : 0,
    '_' => time(),
]);

$graphUrl = '?' . $query;

$fromLabel = date('Y-m-d H:i:s', $graphStart);
$toLabel = date('Y-m-d H:i:s', $graphEnd);
$spanSeconds = $graphEnd - $graphStart;
$spanLabel = human_duration($spanSeconds);
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title><?= h($TITLE) ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
    color-scheme: dark;
    --bg: #0f1117;
    --panel: #171b24;
    --panel2: #202635;
    --panel3: #111621;
    --text: #f2f5fa;
    --muted: #9aa6b8;
    --border: #303848;
}
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background:
        radial-gradient(circle at top left, rgba(87,166,255,0.12), transparent 35%),
        var(--bg);
    color: var(--text);
}
header {
    padding: 22px 28px;
    border-bottom: 1px solid var(--border);
    background: rgba(15,17,23,0.88);
}
h1 {
    margin: 0 0 6px 0;
    font-size: 22px;
}
.sub {
    color: var(--muted);
    font-size: 13px;
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}
main {
    padding: 22px;
    max-width: 1800px;
}
.panel {
    background: rgba(23,27,36,0.96);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px;
    margin-bottom: 18px;
    box-shadow: 0 10px 35px rgba(0,0,0,0.22);
}
.controls {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
    gap: 14px;
    align-items: end;
}
label {
    display: block;
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 6px;
}
select, input, button {
    width: 100%;
    background: var(--panel2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    font-size: 14px;
}
button {
    cursor: pointer;
    background: linear-gradient(180deg, #2c5d91, #224871);
    border-color: #3d74ad;
}
button:hover {
    filter: brightness(1.1);
}
button.secondary {
    background: var(--panel2);
}
button.danger {
    background: #5c2730;
    border-color: #8d3d4b;
}
.checks {
    display: flex;
    gap: 16px;
    align-items: center;
    min-height: 39px;
}
.checks label {
    display: flex;
    gap: 8px;
    align-items: center;
    margin: 0;
    color: var(--text);
}
.checks input {
    width: auto;
}
.quick {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 14px;
}
.quick button {
    width: auto;
    padding: 8px 12px;
}
.graph-panel {
    padding: 14px;
}
.graph-toolbar {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
    margin-bottom: 10px;
    color: var(--muted);
    font-size: 13px;
    flex-wrap: wrap;
}
.graph-frame {
    position: relative;
    overflow: auto;
    padding: 8px;
    background: var(--panel3);
    border: 1px solid var(--border);
    border-radius: 14px;
    text-align: center;
}
.graph-holder {
    position: relative;
    display: inline-block;
    line-height: 0;
}
#graph {
    display: block;
    max-width: none;
    background: #fff;
    border-radius: 8px;
    cursor: crosshair;
    user-select: none;
}
#selection {
    position: absolute;
    top: 0;
    bottom: 0;
    background: rgba(87,166,255,0.22);
    border-left: 2px solid rgba(87,166,255,0.95);
    border-right: 2px solid rgba(87,166,255,0.95);
    display: none;
    pointer-events: none;
}
.footer {
    color: var(--muted);
    font-size: 12px;
}
.smallgrid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 10px;
}
.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #20334e;
    color: #b9d9ff;
    border: 1px solid #31557f;
}
.badge.resolution {
    background: #243f2f;
    color: #bff3d1;
    border-color: #3a7a51;
}
.badge.warning {
    background: #4a3520;
    color: #ffd9a6;
    border-color: #8a6630;
}
.note {
    color: var(--muted);
    font-size: 12px;
    margin-top: 10px;
}
</style>
</head>
<body>
<header>
    <h1><?= h($TITLE) ?></h1>
    <div class="sub">
        <span><?= h($fromLabel) ?> → <?= h($toLabel) ?></span>
        <span class="badge"><?= h($range) ?></span>
        <span class="badge resolution">display/effective: <?= h($resolutionLabel) ?></span>
        <span class="badge">RRD archive: <?= h($archiveLabel) ?></span>
        <?php if ($resolutionSeconds > $archiveStep): ?>
            <span class="badge warning">pixel-consolidated</span>
        <?php endif; ?>
    </div>
</header>

<main>
    <form method="get" class="panel" id="controlForm">
        <input type="hidden" name="start" id="startField" value="<?= (int)$graphStart ?>">
        <input type="hidden" name="end" id="endField" value="<?= (int)$graphEnd ?>">

        <div class="controls">
            <div>
                <label>Time range</label>
                <select name="range" id="rangeSelect" onchange="clearCustomAndSubmit()">
                    <?php foreach (['5m','15m','1h','6h','24h','7d','30d','1y','5y'] as $r): ?>
                        <option value="<?= h($r) ?>" <?= $range === $r ? 'selected' : '' ?>><?= h($r) ?></option>
                    <?php endforeach; ?>
                    <option value="custom" <?= $range === 'custom' ? 'selected' : '' ?>>custom zoom</option>
                </select>
            </div>

            <div>
                <label>Width</label>
                <input name="width" id="widthField" type="number" min="300" max="4000" value="<?= (int)$width ?>">
            </div>

            <div>
                <label>Height</label>
                <input name="height" id="heightField" type="number" min="150" max="2000" value="<?= (int)$height ?>">
            </div>

            <div>
                <label>Style</label>
                <select name="style">
                    <option value="area" <?= $style === 'area' ? 'selected' : '' ?>>Area</option>
                    <option value="line" <?= $style === 'line' ? 'selected' : '' ?>>Line</option>
                    <option value="mirror" <?= $style === 'mirror' ? 'selected' : '' ?> <?= $log ? 'disabled' : '' ?>>Mirror RX/TX</option>
                </select>
            </div>

            <div class="checks">
                <label>
                    <input type="checkbox" name="log" value="1" <?= $log ? 'checked' : '' ?>>
                    Log
                </label>
                <label>
                    <input type="checkbox" name="smooth" value="1" <?= $smooth ? 'checked' : '' ?>>
                    Smooth
                </label>
            </div>

            <div>
                <label>&nbsp;</label>
                <button type="submit">Redraw</button>
            </div>
        </div>

        <div class="quick">
            <?php foreach (['5m','15m','1h','6h','24h','7d','30d','1y','5y'] as $r): ?>
                <button type="button" class="secondary" onclick="goRange('<?= h($r) ?>')"><?= h($r) ?></button>
            <?php endforeach; ?>
            <button type="button" class="secondary" onclick="resizeGraph(1.25)">Larger</button>
            <button type="button" class="secondary" onclick="resizeGraph(0.8)">Smaller</button>
            <button type="button" class="danger" onclick="goRange('1h')">Reset zoom</button>
        </div>

        <div class="note">
            Effective resolution is the coarser value between the RRD archive step and the display/pixel step.
            Long windows may average peaks even when 1-second archive data still exists.
        </div>
    </form>

    <div class="panel graph-panel">
        <div class="graph-toolbar">
            <div>
                <strong>Graph</strong> —
                drag horizontally over the graph to zoom
            </div>
            <div>
                effective:
                <strong><?= h($resolutionLabel) ?></strong>
                —
                pixel:
                <strong><?= h($pixelLabel) ?></strong>
            </div>
        </div>

        <div class="graph-frame">
            <div class="graph-holder" id="graphHolder">
                <img id="graph"
                     src="<?= h($graphUrl) ?>"
                     alt="traffic graph"
                     width="<?= (int)$width ?>"
                     height="<?= (int)$height + 120 ?>"
                     draggable="false">
                <div id="selection"></div>
            </div>
        </div>
    </div>

    <div class="panel footer smallgrid">
        <div>RRD: <?= h($RRD_FILE) ?></div>
        <div>Window: <?= h($spanLabel) ?> / <?= (int)$spanSeconds ?> seconds</div>
        <div>RRD archive resolution: <?= h($archiveLabel) ?></div>
        <div>Pixel/display resolution: <?= h($pixelLabel) ?> per horizontal pixel</div>
        <div>Effective graph resolution: <?= h($resolutionLabel) ?> per plotted point</div>
        <div>Forced rrdtool step: <?= (int)$resolutionSeconds ?> seconds</div>
        <div>Graph width: <?= (int)$width ?> px</div>
        <div>Mode: <?= h($style) ?><?= $log ? ', log scale' : '' ?><?= $smooth ? ', smoothed' : '' ?></div>
    </div>
</main>

<script>
const graph = document.getElementById('graph');
const selection = document.getElementById('selection');
const form = document.getElementById('controlForm');
const startField = document.getElementById('startField');
const endField = document.getElementById('endField');
const rangeSelect = document.getElementById('rangeSelect');

const graphStart = <?= (int)$graphStart ?>;
const graphEnd = <?= (int)$graphEnd ?>;

// Approximate RRDTool plot margins.
// If zoom is slightly offset, tune these values.
const plotLeftMargin = 75;
const plotRightMargin = 25;

let dragging = false;
let dragStartX = 0;
let dragCurrentX = 0;

function localX(event) {
    const rect = graph.getBoundingClientRect();
    return event.clientX - rect.left;
}

function clampPlotX(x) {
    const min = plotLeftMargin;
    const max = graph.clientWidth - plotRightMargin;
    return Math.max(min, Math.min(max, x));
}

function xToEpoch(x) {
    const minX = plotLeftMargin;
    const maxX = graph.clientWidth - plotRightMargin;
    const ratio = (x - minX) / (maxX - minX);
    return Math.round(graphStart + ratio * (graphEnd - graphStart));
}

function updateSelection() {
    const a = clampPlotX(dragStartX);
    const b = clampPlotX(dragCurrentX);
    const left = Math.min(a, b);
    const width = Math.abs(b - a);

    selection.style.left = left + 'px';
    selection.style.width = width + 'px';
    selection.style.display = width > 2 ? 'block' : 'none';
}

graph.addEventListener('mousedown', (e) => {
    dragging = true;
    dragStartX = localX(e);
    dragCurrentX = dragStartX;
    updateSelection();
    e.preventDefault();
});

window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    dragCurrentX = localX(e);
    updateSelection();
});

window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;

    const a = clampPlotX(dragStartX);
    const b = clampPlotX(dragCurrentX);
    const pixelWidth = Math.abs(b - a);

    if (pixelWidth < 12) {
        selection.style.display = 'none';
        return;
    }

    const newStart = Math.min(xToEpoch(a), xToEpoch(b));
    const newEnd = Math.max(xToEpoch(a), xToEpoch(b));

    if (newEnd - newStart < 2) {
        selection.style.display = 'none';
        return;
    }

    startField.value = String(newStart);
    endField.value = String(newEnd);
    rangeSelect.value = 'custom';
    form.submit();
});

function goRange(r) {
    const url = new URL(window.location.href);
    url.searchParams.delete('start');
    url.searchParams.delete('end');
    url.searchParams.set('range', r);
    window.location.href = url.toString();
}

function clearCustomAndSubmit() {
    if (rangeSelect.value !== 'custom') {
        startField.removeAttribute('name');
        endField.removeAttribute('name');
    }
    form.submit();
}

function resizeGraph(factor) {
    const w = document.getElementById('widthField');
    const h = document.getElementById('heightField');

    w.value = Math.max(300, Math.min(4000, Math.round(Number(w.value) * factor)));
    h.value = Math.max(150, Math.min(2000, Math.round(Number(h.value) * factor)));

    form.submit();
}
</script>
</body>
</html>
