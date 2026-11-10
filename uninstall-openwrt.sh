#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

if [ "$(id -u)" != "0" ]; then
	echo "error: run this uninstaller as root" >&2
	exit 1
fi

if [ -x /etc/init.d/ipc-discovery ]; then
	/etc/init.d/ipc-discovery stop || true
	/etc/init.d/ipc-discovery disable || true
fi

rm -f /usr/bin/ipc-discovery
rm -f /etc/init.d/ipc-discovery
rm -f /etc/config/ipc-discovery
rm -f /var/run/ipc-discovery.sock
rm -f /usr/share/luci/menu.d/luci-app-ipc-discovery.json
rm -f /usr/share/rpcd/acl.d/luci-app-ipc-discovery.json
rm -f /usr/share/rpcd/ucode/luci.ipc-discovery
rm -rf /www/luci-static/resources/view/ipc-discovery
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/* 2>/dev/null || true

[ ! -x /etc/init.d/rpcd ] || /etc/init.d/rpcd restart
if [ -x /etc/init.d/nginx ]; then
	/etc/init.d/nginx restart
elif [ -x /etc/init.d/uhttpd ]; then
	/etc/init.d/uhttpd restart
fi

echo "IP Camera Discovery removed."
