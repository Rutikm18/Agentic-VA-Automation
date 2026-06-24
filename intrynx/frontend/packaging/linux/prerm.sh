#!/bin/sh
# Runs before package removal (.deb prerm / .rpm %preun). Stops + disables the service.
set -e
APP=netagent
systemctl stop "$APP".service 2>/dev/null || true
systemctl disable "$APP".service 2>/dev/null || true
# State dir (/var/lib/netagent) and the netagent user are left in place intentionally so an
# upgrade keeps the probe's identity. A purge can remove them manually.
