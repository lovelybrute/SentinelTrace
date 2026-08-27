# Threat-intelligence account setup

SentinelTrace supports optional VirusTotal and AbuseIPDB lookups. Never commit
API keys to GitHub or place them in frontend `VITE_*` variables.

## VirusTotal

1. Create or sign in to a VirusTotal Community account at
   https://www.virustotal.com/gui/join-us.
2. Open your profile/API key page and copy the personal API key.
3. In Render, open **sentineltrace-backend → Environment** and set
   `VIRUSTOTAL_API_KEY`.

The public service is intended for non-commercial use and submitted artifacts
may be shared with the security community. SentinelTrace only performs domain
and IP report retrieval; it does not upload email contents or attachments.

## AbuseIPDB

1. Register at https://www.abuseipdb.com/register.
2. Open the account API settings and create a key named `SentinelTrace`.
3. In Render, set `ABUSEIPDB_API_KEY`.

Free individual accounts currently advertise 1,000 checks/reports per day.
SentinelTrace caches a lookup for 15 minutes to conserve the allowance.

## Verification

After Render redeploys, check:

```text
https://sentineltrace-backend.onrender.com/health
https://sentineltrace-backend.onrender.com/intel/lookup?indicator=8.8.8.8
```

The health response reports each provider as `configured` without exposing its
secret. Reputation is treated as an investigative signal, not attribution.
