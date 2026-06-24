#!/bin/sh
# Runs after package install (.deb postinst / .rpm %post). Creates the least-priv user,
# state dir, and config; enables the service. Idempotent.
set -e

APP=netagent

# Dedicated unprivileged system user (no login, no home shell).
if ! id "$APP" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$APP" 2>/dev/null \
        || adduser --system --no-create-home --group "$APP" 2>/dev/null || true
fi

install -d -o "$APP" -g "$APP" -m 0750 /var/lib/"$APP"      # state dir
install -d -m 0755 /etc/"$APP"
if [ ! -f /etc/"$APP"/"$APP".env ]; then
    install -m 0640 /usr/share/"$APP"/"$APP".env.example /etc/"$APP"/"$APP".env || true
    chown root:"$APP" /etc/"$APP"/"$APP".env 2>/dev/null || true
fi

systemctl daemon-reload 2>/dev/null || true
systemctl enable "$APP".service 2>/dev/null || true
echo "Installed. Edit /etc/$APP/$APP.env (enroll token), then: systemctl start $APP"
