# Attack Surface Ranking: cliniko.com
**Generated:** 2026-06-04 22:19

## Stats
- Subdomains   : 8450
- Live hosts   : 4650
- Total URLs   : 254660
- P1 targets   : 9
- P2 targets   : 0
- Kill list    : 0
- Prev tested  : 0

## Start Here
> Parse error — check recon output

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

## Priority 2 (after P1)

## Kill List (skip)

## Memory Context
- numeric id in /api/v1/users/{id} on rails → IDOR - read other users data
- ?redirect= parameter on any → open redirect to oauth token theft
- /graphql introspection enabled on graphql → schema leak leads to IDOR discovery
- ?file= or ?path= parameter on php → LFI - read /etc/passwd
- /api/v1/ endpoints with no auth header check on express → IDOR on user objects