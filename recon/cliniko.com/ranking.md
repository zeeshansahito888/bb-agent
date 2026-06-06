# Attack Surface Ranking: cliniko.com
**Generated:** 2026-06-05 02:01

## Stats
- Subdomains   : 8450
- Live hosts   : 4650
- Total URLs   : 254660
- P1 targets   : 3
- P2 targets   : 2
- Kill list    : 2
- Prev tested  : 0

## Start Here
> Start with IDOR candidates and API endpoints as they are high priority based on the ranking rules.

## Priority 1 (start here)

1. **https://www.facebook.com/profile.php?id=100069966975776**
   - Why   : Potential IDOR vulnerability as it references a specific Facebook profile.
   - Tech  : N/A
   - Test  : Test for ability to view other users' profiles without proper authorization.
   - Class : IDOR

2. **https://api.au1.cliniko.com/v1/appointments/**
   - Why   : API endpoint with ID parameter, potentially allowing unauthenticated access to appointment data.
   - Tech  : N/A
   - Test  : Send requests with different IDs and observe responses for unauthorized access.
   - Class : IDOR

3. **https://api.au1.cliniko.com/v1/appointments/1/invoices?page=1**
   - Why   : API endpoint with ID parameter, potentially allowing unauthenticated access to appointment invoices.
   - Tech  : N/A
   - Test  : Send requests with different IDs and observe responses for unauthorized access.
   - Class : IDOR

## Priority 2 (after P1)

1. **http://docs.angularjs.org/api/angular.element**
   - Why  : Interesting endpoint without ID parameter, could be useful for further exploration of the application.
   - Test : Check if this endpoint is accessible and what information it provides.

2. **http://docs.angularjs.org/api/ng.**
   - Why  : Potential interesting endpoint related to AngularJS documentation.
   - Test : Explore similar endpoints for more information about the application's technology stack.

## Kill List (skip)
- `https://a-a-podiatrists.cliniko.com` — CDN host, likely not a direct target for exploitation.
- `http://0.cliniko.com` — Static page or redirect, unlikely to contain sensitive information.

## Memory Context
- ============================================================
    Results for: "IDOR vulnerability API cliniko.com"
- ============================================================
    Results for: "bug bounty high severity findings"
- ============================================================
    Results for: "SQL injection SSRF bypass"