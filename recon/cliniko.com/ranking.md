# Attack Surface Ranking: cliniko.com
**Generated:** 2026-06-03 18:37

## Stats
- Subdomains   : 8450
- Live hosts   : 4650
- Total URLs   : 254660
- P1 targets   : 11
- P2 targets   : 1
- Kill list    : 2
- Prev tested  : 0

## Start Here
> Start with the API endpoints as they are more likely to contain sensitive data and have potential IDOR vulnerabilities.

## Priority 1 (start here)

1. **https://docs.api.cliniko.com/runtime/chunks/GraphQLDocs-73P2KXZM.js**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

2. **https://status.cliniko.com/subscriptions/incident.json**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

3. **https://status.cliniko.com/subscriptions/new-email**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

4. **https://status.cliniko.com/subscriptions/new-sms**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

5. **https://status.cliniko.com/subscriptions/track_attempt**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

6. **https://status.cliniko.com/subscriptions/verify-email-otp**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

7. **https://status.cliniko.com/subscriptions/verify-otp**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

8. **https://status.cliniko.com/subscriptions/webhook.json**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

9. **https://subscriptions.statuspage.io/slack_authentication/kickoff?page_code=njcmcp9gx7rh**
   - Why   : GraphQL/WebSocket — always P1
   - Test  : test introspection, IDOR via queries
   - Class : graphql/websocket

10. **https://api.au1.cliniko.com/v1/appointments**
   - Why   : API endpoint with pagination parameters, potential IDOR or data leakage.
   - Tech  : API
   - Test  : Test for IDOR by manipulating the 'page' and 'per_page' query parameters without authentication.
   - Class : IDOR

11. **https://api.au1.cliniko.com/v1/appointments/1/invoices**
   - Why   : API endpoint with pagination parameters, potential IDOR or data leakage.
   - Tech  : API
   - Test  : Test for IDOR by manipulating the 'page' query parameter without authentication.
   - Class : IDOR

## Priority 2 (after P1)

1. **https://www.facebook.com/profile.php?id=100069966975776**
   - Why  : Potential IDOR if the profile can be accessed without proper authorization.
   - Test : Attempt to access other user profiles by changing the 'id' parameter.

## Kill List (skip)
- `https://a-a-podiatrists.cliniko.com` — 301 redirect, likely CDN or static content, not a direct target for exploitation.
- `http://0.cliniko.com` — 301 redirect, likely CDN or static content, not a direct target for exploitation.

## Memory Context
- numeric id in /api/v1/users/{id} on rails → IDOR - read other users data
- ?redirect= parameter on any → open redirect to oauth token theft
- /graphql introspection enabled on graphql → schema leak leads to IDOR discovery
- ?file= or ?path= parameter on php → LFI - read /etc/passwd
- /api/v1/ endpoints with no auth header check on express → IDOR on user objects