#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

if [ "$(id -u)" != "0" ]; then
	echo "error: run this installer as root" >&2
	exit 1
fi

BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
APP_DIR="$BASE_DIR/luci-app-ipc-discovery"

if ! command -v python3 >/dev/null 2>&1; then
	echo "error: python3 is missing; install python3-light and python3-xml first" >&2
	exit 1
fi

if ! python3 -c 'import fcntl, socket, xml.etree.ElementTree' >/dev/null 2>&1; then
	echo "error: required Python modules are missing; install python3-light and python3-xml" >&2
	exit 1
fi

if [ ! -d /www/luci-static/resources ]; then
	echo "error: LuCI resources were not found under /www/luci-static/resources" >&2
	exit 1
fi

mkdir -p /usr/bin
mkdir -p /etc/config
mkdir -p /etc/init.d
mkdir -p /usr/share/luci/menu.d
mkdir -p /usr/share/rpcd/acl.d
mkdir -p /usr/share/rpcd/ucode
mkdir -p /www/luci-static/resources/view/ipc-discovery

cp "$BASE_DIR/ipc-discovery.py" /usr/bin/ipc-discovery
cp "$APP_DIR/root/etc/init.d/ipc-discovery" /etc/init.d/ipc-discovery
if [ ! -e /etc/config/ipc-discovery ]; then
	cp "$APP_DIR/root/etc/config/ipc-discovery" /etc/config/ipc-discovery
fi
cp "$APP_DIR/root/usr/share/luci/menu.d/luci-app-ipc-discovery.json" \
	/usr/share/luci/menu.d/luci-app-ipc-discovery.json
cp "$APP_DIR/root/usr/share/rpcd/acl.d/luci-app-ipc-discovery.json" \
	/usr/share/rpcd/acl.d/luci-app-ipc-discovery.json
cp "$APP_DIR/root/usr/share/rpcd/ucode/luci.ipc-discovery" \
	/usr/share/rpcd/ucode/luci.ipc-discovery
cp "$APP_DIR/htdocs/luci-static/resources/view/ipc-discovery/overview.js" \
	/www/luci-static/resources/view/ipc-discovery/overview.js

chmod 0755 /usr/bin/ipc-discovery
chmod 0755 /etc/init.d/ipc-discovery
chmod 0600 /etc/config/ipc-discovery
chmod 0755 /usr/share/rpcd/ucode/luci.ipc-discovery
chmod 0644 /usr/share/luci/menu.d/luci-app-ipc-discovery.json
chmod 0644 /usr/share/rpcd/acl.d/luci-app-ipc-discovery.json
chmod 0644 /www/luci-static/resources/view/ipc-discovery/overview.js

rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/* 2>/dev/null || true

[ ! -x /etc/init.d/rpcd ] || /etc/init.d/rpcd restart
if [ -x /etc/init.d/nginx ]; then
	/etc/init.d/nginx restart
elif [ -x /etc/init.d/uhttpd ]; then
	/etc/init.d/uhttpd restart
fi
/etc/init.d/ipc-discovery enable
/etc/init.d/ipc-discovery restart

echo "Installed. Open LuCI: Network -> IP Camera Discovery"
echo "CLI test: /usr/bin/ipc-discovery --client scan --json --pretty"
