# Attack Surface Ranking: cliniko.com
**Generated:** 2026-06-04 22:35

## Stats
- Subdomains   : 8450
- Live hosts   : 4650
- Total URLs   : 254660
- P1 targets   : 12
- P2 targets   : 1
- Kill list    : 2
- Prev tested  : 0

## Start Here
> Start with the IDOR candidates and API endpoints as they are high priority based on the ranking rules.

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

10. **https://www.facebook.com/profile.php?id=100069966975776**
   - Why   : Potential IDOR as it involves a specific user profile.
   - Tech  : N/A
   - Test  : Test for read-only or write access to the profile information.
   - Class : IDOR

11. **https://api.au1.cliniko.com/v1/appointments/**
   - Why   : API endpoint with ID params, likely unauthenticated access.
   - Tech  : N/A
   - Test  : Try to fetch or modify appointment data without authentication.
   - Class : IDOR

12. **https://api.au1.cliniko.com/v1/appointments/1**
   - Why   : API endpoint with ID params, likely unauthenticated access.
   - Tech  : N/A
   - Test  : Try to fetch or modify appointment data without authentication.
   - Class : IDOR

## Priority 2 (after P1)

1. **https://api.au1.cliniko.com/v1/appointments?page=2&per_page=100**
   - Why  : Interesting endpoint for pagination and potentially unauthenticated access.
   - Test : Test for large per_page values to see if it returns more data than expected.

## Kill List (skip)
- `https://a-a-podiatrists.cliniko.com` — CDN host, likely not a direct target.
- `http://0.cliniko.com` — Static page or redirect, not a direct target.

## Memory Context
- mempalace on ? → ?
- mempalace on ? → ?
- mempalace on ? → ?