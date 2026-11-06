#!/bin/sh
# Install the native PCU20 daemon on FreeBSD 13.5 amd64 server.
set -eu
if [ "$(id -u)" != 0 ]; then echo "Run as root." >&2; exit 1; fi
if [ "$(uname -s)" != FreeBSD ] || [ "$(uname -m)" != amd64 ]; then
    echo "This binary targets FreeBSD amd64." >&2; exit 1
fi
case "$(freebsd-version -u)" in
    13.5-*) ;;
    *) echo "This bundle targets FreeBSD 13.5-RELEASE." >&2; exit 1 ;;
esac

bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$bundle"
while read -r expected relative; do
    if [ "$(sha256 -q "$relative")" != "$expected" ]; then
        echo "Checksum mismatch: $relative" >&2; exit 1
    fi
done < SHA256SUMS

account="pcu20"
if ! id "$account" >/dev/null 2>&1; then
    echo "Create the service account pcu20 before installing:" >&2
    echo "pw useradd -n pcu20 -d /nonexistent -s /usr/sbin/nologin -w no" >&2
    exit 1
fi
account_group=$(id -gn "$account")

if [ -x /usr/local/etc/rc.d/pcu20d ]; then
    if service pcu20d onestatus >/dev/null 2>&1; then service pcu20d onestop; fi
fi

install -d -o root -g wheel -m 0755 /usr/local/sbin /usr/local/etc/rc.d
install -o root -g wheel -m 0555 pcu20d /usr/local/sbin/pcu20d
install -o root -g wheel -m 0555 freebsd/pcu20d /usr/local/etc/rc.d/pcu20d
if [ -e /usr/local/etc/pcu20d.ini ]; then
    install -o root -g "$account_group" -m 0640 pcu20d.ini /usr/local/etc/pcu20d.ini.new
    echo "Existing pcu20d.ini preserved; bundled configuration saved as pcu20d.ini.new."
else
    install -o root -g "$account_group" -m 0640 pcu20d.ini /usr/local/etc/pcu20d.ini
fi
chgrp "$account_group" /usr/local/etc/pcu20d.ini
chmod 0640 /usr/local/etc/pcu20d.ini
install -d -o root -g wheel -m 0755 /srv
if [ ! -e /srv/pcu20 ]; then
    install -d -o "$account" -g "$account_group" -m 0750 /srv/pcu20
fi
sysrc pcu20d_enable=YES
sysrc pcu20d_account="$account"
service pcu20d start
service pcu20d status
