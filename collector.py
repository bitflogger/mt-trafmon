#!/usr/bin/env python3
import os
import sys
import time
import argparse
import logging

# The non-default libraries, to be installed
from librouteros import connect
import rrdtool

# --- CONFIGURATION BEGIN ---

# The IP of your router (default provided)
HOST = "192.168.88.1"
# The admin user of your router (default provided)
USER = "admin"

# The password from the user above
# No default provided./ Put your own password here
# NB: DO NOT put this file in the web server directory
PASSWORD = ""

# The interface that connects to your internet connection (default provided)
INTERFACE = "ether1"

# This is the file where all measurements will be stored.
# NB: With the default settings, this file will be initialized immediately
# (as RRD files are) with a size of ~835MB
# NB: It's best not to locate this file in the web server directory
RRD_FILE = "/var/www/koutstaal.com/trafmon/traffic.rrd"

# --- CONFIGURATION END ---


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="suppress normal collection logging"
    )
    return parser.parse_args()


ARGS = parse_args()
VERBOSE = sys.stdout.isatty() and not ARGS.quiet

logging.basicConfig(
    level=logging.INFO if VERBOSE else logging.ERROR,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr
)


def init_rrd():
    if os.path.exists(RRD_FILE):
        return
    rrdtool.create(
        RRD_FILE,
        "--start", "now-2",
        "--step", "1",

        "DS:rx:GAUGE:3:0:U",
        "DS:tx:GAUGE:3:0:U",

        # 1 year raw 1-second data
        "RRA:AVERAGE:0.5:1:31557600",

        # 5 years 10-second averages
        "RRA:AVERAGE:0.5:10:15778800",

        # 5 years 1-minute average + max
        "RRA:AVERAGE:0.5:60:2629800",
        "RRA:MAX:0.5:60:2629800",

        # 10 years 5-minute average + max
        "RRA:AVERAGE:0.5:300:1051920",
        "RRA:MAX:0.5:300:1051920",
)


def connect_api():
    return connect(
        host=HOST,
        username=USER,
        password=PASSWORD,
        timeout=10
    )


def read_traffic_once(api):
    cmd = api.path("interface")

    rows = tuple(cmd(
        "monitor-traffic",
        interface=INTERFACE,
        once=True
    ))

    if not rows:
        raise RuntimeError("No data returned from monitor-traffic")

    row = rows[0]

    rx = int(row.get("rx-bits-per-second", 0))
    tx = int(row.get("tx-bits-per-second", 0))

    return rx, tx


def sleep_to_next_second():
    now = time.time()
    time.sleep(max(0.0, 1.0 - (now % 1.0)))


def collect():
    init_rrd()
    api = connect_api()

    if VERBOSE:
        logging.info("Connected to MikroTik %s, collecting %s", HOST, INTERFACE)

    while True:
        rx, tx = read_traffic_once(api)

        try:
            rrdtool.update(RRD_FILE, f"N:{rx}:{tx}")
            if VERBOSE:
                logging.info("RX=%s bps TX=%s bps", rx, tx)
        except rrdtool.error as e:
            logging.warning("RRD update skipped: %s", e)

        sleep_to_next_second()


if __name__ == "__main__":
    while True:
        try:
            collect()
        except Exception as e:
            logging.error("Collector error: %s", e)
            time.sleep(5)
            
