# CloudPatrol Java Backend Security Audit

**Prepared for:** Enormity Tech MySTI R&D application evidence pack  
**Scope:** Decompiled CloudPatrol Java controller layer and Enormity Sidecar API mitigation layer  
**Date:** 2026-04-23  
**Auditor:** Enormity technical assessment using locally decompiled bytecode  

## 1. Executive Summary

This audit reviewed the decompiled CloudPatrol Java backend controllers recovered from the deployed Tomcat application under `/opt/CloudPatrol/appFile/web/ROOT/WEB-INF/classes/com/tour/controller` and compared the OEM implementation with the Enormity-owned Node.js sidecar API at `/opt/enormity-sidecar/server.js`.

The review found repeated use of dynamically concatenated JPQL and native SQL strings in the OEM Java controller layer. Several endpoints concatenate HTTP request parameters directly into database queries and then execute them through `EntityManager.createQuery`, `EntityManager.createNativeQuery`, or `SqlSearchUtil.queryList`. The highest-risk areas are patrol history, alarm history, dashboard/report queries, content detail lookups, site/sound data, and tour statistics.

The Enormity Sidecar API was implemented as an in-house mitigation layer. It uses `mysql2` parameterised queries via `pool.execute(sql, params)`, validates date formats, validates report type selection, and returns consistent JSON responses. This materially reduces SQL injection exposure for Enormity-owned analytics/report endpoints because user input is passed as bind parameters instead of interpolated query text.

Important note: the sidecar currently improves query safety but should still receive a dedicated API authentication control before any external government or production integration use. Recommended controls are API key/JWT validation at nginx or Express middleware, rate limiting, and read-only MySQL credentials.

## 2. Source and Methodology

### 2.1 Decompiled source locations

- OEM controller source: `/opt/enormity-decompiled/sources/com/tour/controller/*.java`
- Sidecar source: `/opt/enormity-sidecar/server.js`
- Full decompile report: `/opt/enormity-decompiled/DECOMPILE_REPORT.md`

### 2.2 Decompiler note

`jadx 1.5.0` could not run on the server because the host runtime is OpenJDK 8 and JADX 1.5.0 requires Java 11 bytecode support. CFR 0.152 was used as a Java 8-compatible fallback. The source is decompiled source and may not match original formatting, but it is sufficient to identify query construction and authentication patterns.

### 2.3 Audit commands used

```bash
for f in /opt/enormity-decompiled/sources/com/tour/controller/*.java; do
  echo "=== $f ==="
  grep -n "concat\|+.*Param\|+.*param\|String.*query\|JPQL\|createQuery" "$f" 2>/dev/null | head -10
done

rg -n "createQuery\(|createNativeQuery\(|sqlSearchUtil\.query|queryStr =|querySql =" \
  /opt/enormity-decompiled/sources/com/tour/controller

rg -n "pool\.execute|validateDateParam|companyWhere|dateRange" \
  /opt/enormity-sidecar/server.js
```

## 3. SQL Injection Vulnerabilities Found

### Finding SQL-01: Patrol history query concatenates request parameters

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/HistoryController.java`  
**Endpoint:** `GET /history/getHistorydatas`  
**Lines:** 102-133  
**Risk:** Critical

**Evidence:**

```java
String deptids = request.getParameter("DeptID");
String BeginTime = request.getParameter("BeginTime");
String EndTime = request.getParameter("EndTime");
String queryStr = "... from Historydatas h where h.deptid in (" + deptids + ") ";
String queryTotal = "select count(1) from Historydatas h where h.deptid in (" + deptids + ")  ";
queryStr = queryStr + " and h.guardid in ( " + guardids + " ) ";
queryStr = queryStr + " and h.siteid in ( " + siteids + " ) ";
queryStr = queryStr + " and h.readercode like ('%" + readercodes + "%') ";
queryStr = queryStr + " and h.historydatasPK.happentime between '" + BeginTime + "' and '" + EndTime + "' order by h.historydatasPK.happentime";
Query query = this.em.createQuery(queryStr);
```

**Impact:** An authenticated or exposed caller can influence `DeptID`, `GuardID`, `SiteID`, `Readercode`, `BeginTime`, and `EndTime`. Because those values are inserted directly into JPQL, malformed input could alter query logic, bypass filters, expose other department data, or cause denial of service through expensive queries.

**Root cause:** Dynamic JPQL construction with untrusted request parameters.

**Required remediation:** Replace string concatenation with typed DTO validation and named JPQL parameters. List filters should be parsed into numeric arrays and bound as parameter lists.

### Finding SQL-02: Alarm history query concatenates request parameters

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/AlarmdatasController.java`  
**Endpoint:** Alarm data query controller method  
**Lines:** 120-159  
**Risk:** Critical

**Evidence:**

```java
String BeginTime = request.getParameter("BeginTime");
String EndTime = request.getParameter("EndTime");
String queryStr = "... from Alarmdatas a where a.deptid in (" + deptids + ") and a.alarmtype != 3 ";
queryStr = queryStr + " and a.siteid in ( " + siteids + " ) ";
queryStr = queryStr + " and a.readercode like ('%" + readercodes + "%') ";
queryStr = queryStr + " and a.instantdata = " + processState + " ";
queryStr = queryStr + " and a.happentime between '" + BeginTime + "' and '" + EndTime + "' order by a.happentime desc";
Query query = this.em.createQuery(queryStr);
```

**Impact:** Similar to SQL-01, with exposure of alarm events, alarm status, reader codes, guard names, site names, timestamps, and GPS coordinates.

**Root cause:** Direct string concatenation into JPQL and insufficient validation of numeric/date filters.

### Finding SQL-03: Content lookup uses native SQL and JPQL concatenation

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/ContentController.java`  
**Endpoints:** `GET /content/getContents`, content detail methods  
**Lines:** 97-107, 299, 317  
**Risk:** High

**Evidence:**

```java
String selSiteID = request.getParameter("SiteID");
String selPlanID = request.getParameter("PlanID");
Query query = this.entityManager.createQuery("select s.contentid, s.contenttitle, s.contentdesc, s.committype from VSitecontents s where s.siteid = " + SiteID + " and s.planid=" + PlanID);
```

```java
this.entityManager.createNativeQuery("select t.contentchoice,t.contentdes from tourcontentdetail t where t.historyid = " + selID + " ...").getResultList()
```

```java
this.entityManager.createNativeQuery("select t.contentchoice,t.contentdes from tourcontentdetail t where t.historyid = " + selID + " and t.contentid = " + detail.getContentid().getId() + " ...").getResultList()
```

**Impact:** The line 107 method performs numeric validation before interpolation, reducing exploitability. Lines 299 and 317 are native SQL construction points dependent on upstream integer parsing and internal object values. This remains a fragile pattern and should be replaced with bind parameters.

**Root cause:** Native SQL assembly through string concatenation.

### Finding SQL-04: Real-time data push queries concatenate user/company/date data

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/DataPushController.java`  
**Endpoint area:** WebSocket/dashboard data push helper methods  
**Lines:** 62, 71, 81, 90, 108  
**Risk:** Medium

**Evidence:**

```java
String querySql = "select m.* from ( select deptid from userdepts where userid = " + userId + " ) ud ...";
String querySql = "select count(r.dataid) ... where companyid = " + companyId + " ...";
String querySql = "... FROM realdatas h WHERE h.HAPPENTIME > '" + currentDateStr + "' ...";
String querySql = "... WHERE COMPANYID = " + companyId + " AND BEGINTIME <= '" + nowDateTimeStr + "' ...";
String querySql = "... WHERE a.pushed = 0 and ((a.HAPPENTIME > '" + currentDateStr + "' ...";
```

**Impact:** These values appear to be derived from the authenticated context and server-generated timestamps rather than raw query parameters. The immediate external exploitability is therefore lower than SQL-01/SQL-02, but the coding pattern is still unsafe and can become exploitable if helper inputs are ever influenced externally.

**Root cause:** Native SQL construction without bind parameters.

### Finding SQL-05: Tour statistics and dashboard/report queries concatenate filters

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/TourDataController.java`  
**Endpoint area:** tour statistics/report data  
**Lines:** 135-152, 170-203, 345-353, 408-430  
**Risk:** High

**Evidence:**

```java
queryStr = queryStr + " and t.deptid in (" + deptids + ") ";
queryStr = queryStr + " and t.guardid in (" + guardids + ") ";
queryStr = queryStr + " and t.planid in (" + planids + ") ";
Query query1 = this.em.createQuery(queryStr1 + queryStr + " and t.begintime >= '" + beginTime + "' ...");
```

```java
queryStr = queryStr + " and t.deptid in (" + deptids + ")";
queryStr = queryStr + " and t.siteid IN (" + siteids + ")";
queryStr = queryStr + " AND t.begintime >= '" + BeginTime + "' ...";
Query query = this.em.createQuery(queryStr);
```

**Impact:** Tour statistics are core reporting data. Injection could alter report scope, hide omitted patrols, inflate completion rates, or expose unauthorized departments/sites.

**Root cause:** Dynamic query text from request-derived list and date filters.

### Finding SQL-06: DashboardController has multiple dynamic native/JPQL queries

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/DashboardController.java`  
**Lines found:** 132, 135, 137, 140, 143, 145, 196-218, 349  
**Risk:** High

**Evidence summary:** The controller builds native SQL counts using `deptids`, company IDs, and date strings, then executes them through `createNativeQuery` or `createQuery`. Examples include department-scoped site, guard, plan, and dashboard statistic queries.

**Impact:** Dashboard metrics could be manipulated or expanded beyond the authorized department scope if filter values are externally controllable.

**Root cause:** Dynamic SQL/JPQL and list filters embedded directly in query text.

### Finding SQL-07: SiteController uses repeated dynamic native SQL for site/sound data

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/SiteController.java`  
**Lines found:** 745, 911, 943, 944, 979, 1114, 1311  
**Risk:** Medium to High

**Evidence summary:** The controller concatenates site IDs and department ID lists into native SQL queries. Some lines use parsed integers; others use helper-generated lists such as `getUserdeptids()`. The use of helper-generated strings still leaves fragile trust assumptions.

**Impact:** Unauthorized site discovery or query manipulation if helper/list input is compromised or insufficiently validated.

### Finding SQL-08: ModuleformController concatenates module codes

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/ModuleformController.java`  
**Line:** 51, executed at line 102  
**Risk:** Medium

**Evidence:**

```java
StringBuilder queryStr = new StringBuilder("select m.moduleid,m.modulecode,m.modulename,m.parentmodulecode from Modules m where m.parentmodulecode = '" + parentmodulecode + "' and m.modulelanguage = " + modulelanguage + " and ");
Query query = this.em.createNativeQuery(queryStr.toString());
```

**Impact:** If `parentmodulecode` or reader-type derived values are influenced by user/company configuration, menu/module lookup can be query-manipulated.

### Finding SQL-09: ExportController report support query uses dynamic SQL

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/ExportController.java`  
**Endpoint:** `GET /export/exportTableForPlan` and report/export endpoints delegated to services  
**Lines:** 223-226, 255-318, 341-344  
**Risk:** Medium

**Evidence:**

```java
int deptID = Integer.parseInt(request.getParameter("DeptID"));
String queryPlanAndScheduleSql = "select ... from plans where deptid = " + deptID + " ... where 1 = " + searchPlanReaderFlag + " ...";
List planDataList = this.sqlSearchUtil.queryList(queryPlanAndScheduleSql, ExportSimplePlanData.class);
```

**Impact:** The directly shown query uses parsed integers, reducing direct injection risk. However, report methods delegate raw `HttpServletRequest` to services such as `exportDataSearchService.getExportTourData(request, companys)` and `customExportService.exportHistoryExcel(request, response)`. Those service-layer implementations were outside the controller scan and require separate service-level audit.

### Finding SQL-10: Additional dynamic query locations

The scan also found dynamic query construction in these controllers:

| File | Lines | Risk | Notes |
|---|---:|---|---|
| `ReadersController.java` | 163 | Low-Medium | Concatenates user ID from service result. |
| `UserDeptsController.java` | 62 | Low-Medium | Concatenates user ID from service result. |
| `ReadDataController.java` | 416 | Low-Medium | Concatenates `Ut.GetUserID()` into native query. |
| `SoundsController.java` | 178, 239, 242, 244, 254, 262 | Medium | Mix of parsed integers, company/user IDs, and department code prefix. |
| `CompanysController.java` | 226, 232, 238, 256, 262, 268 | Medium | Concatenates year/month fragments into native SQL. |
| `ContentController.java` | 388-389 | Low | Uses `?1`, but passes comma-separated string into an `IN` clause; likely logic bug and may not expand list as intended. |

## 4. Authentication and Authorization Weaknesses Found

### Finding AUTH-01: Password reset emails existing password in plaintext

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/LoginController.java`  
**Endpoint:** `POST /login/pwd/{companyCode}/{userName}`  
**Lines:** 232-278  
**Risk:** Critical

**Evidence:**

```java
String content = "... Retrieve user【" + userName + "】password to " + thisUser.getUserpassword() + ", Please login again.";
this.cloudEmailSendService.send(finalEmail, subject, finalContent, null);
```

**Impact:** The system stores or can recover user passwords in plaintext or reversible form. Sending the current password by email violates modern authentication security standards and increases credential exposure risk through email compromise, logs, mailbox forwarding, and support access.

**Required remediation:** Store passwords using one-way adaptive hashing such as bcrypt/Argon2id/PBKDF2. Password reset should generate a single-use, time-limited reset token and never reveal the existing password.

### Finding AUTH-02: Login compares decrypted password to stored password

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/LoginController.java`  
**Endpoint:** `POST /token`  
**Lines:** 140-170  
**Risk:** High

**Evidence:**

```java
String passwd = Ut.aesDecrpyt(UserPwd);
List<Users> list = this.usersService.findByUsernameAndUserpasswordAndCompanyid(UserName, passwd, company);
if (!passwd.equals(users.getUserpassword())) { ... }
```

**Impact:** Password verification appears to use decrypted client-provided password compared to stored password, rather than adaptive hash verification. This suggests weak password storage and a larger blast radius if the database is exposed.

### Finding AUTH-03: Integration API can mint admin token from shared API key

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/LoginController.java`  
**Endpoint:** `GET /system/integrations/token`  
**Lines:** 310-360  
**Risk:** High

**Evidence:**

```java
if (dataIntegrationParam == null || !apiKey.equals(dataIntegrationParam.getParamvalue())) { ... }
Users adminUser = usersList.get(0);
LoginPara loginParaByUser = this.getLoginParaByUser(adminUser, companyInfo, true, companyCode, true);
adminUserToken = loginParaByUser.getToken();
```

**Impact:** Possession of a single integration API key can produce an admin token. If the API key leaks, an attacker can bypass normal user authentication and obtain privileged access.

**Required remediation:** Scope integration tokens, rotate keys, add HMAC or OAuth2-style client credentials, log all issuance, and avoid returning full admin-equivalent user tokens.

### Finding AUTH-04: Quick integration user key enables SSO-style login path

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/LoginController.java`  
**Endpoints:** `GET /system/integrations/users`, `GET /system/integrations/auth`  
**Lines:** 363-423  
**Risk:** High

**Evidence:**

```java
String encrypt = AESUtil.encrypt(username);
String userName = AESUtil.decrypt(userKey);
List<Users> usersList = this.usersService.findByUsernameLikeAndCompanyid(userName, companyInfo);
LoginPara loginParaByUser = this.getLoginParaByUser(users, companyInfo, true, companyCode, true);
ssoLoginPara.setPasswd(users.getUserpassword());
```

**Impact:** The SSO path appears to rely on encrypted username material and returns a login object that includes the user's password. If encryption keys are static or recoverable, the path can become an authentication bypass.

### Finding AUTH-05: Long-lived/reused Redis token behavior

**File:** `/opt/enormity-decompiled/sources/com/tour/controller/LoginController.java`  
**Lines:** 501-524  
**Risk:** Medium

**Evidence:**

```java
tokenKey = "shiro:token:" + UsrID;
if (dataIntegration) {
    token = JWTUtil.createDataIntegrationToken(users, "1");
    RedisUtil.set(tokenKey, token);
} else if (RedisUtil.existsKey(tokenKey).booleanValue()) {
    token = RedisUtil.get(tokenKey);
    ...
}
```

**Impact:** Non-guest users may reuse a token stored under a stable user ID key. Data integration tokens are stored without an explicit TTL in this snippet. Token reuse reduces session isolation and may complicate revocation.

## 5. Missing Input Validation

The OEM Java code shows inconsistent validation. Some controllers call `Integer.parseInt` or `Ut.isNumeric`, but high-risk endpoints accept complex filter strings and dates without strict validation.

| Area | File/lines | Missing validation |
|---|---:|---|
| History filters | `HistoryController.java:102-131` | `DeptID`, `GuardID`, `SiteID` comma-list validation; `Readercode` allowlist; date format/range checks; max page size bounds. |
| Alarm filters | `AlarmdatasController.java:120-157` | `siteids`, `readercodes`, `processState`, date format/range checks; max page size bounds. |
| Tour statistics | `TourDataController.java:141-152`, `184-193` | List filters and date windows are concatenated without strict schemas. |
| Dashboard | `DashboardController.java:132-218` | Department lists and date strings should be parsed and bound, not concatenated. |
| Content detail | `ContentController.java:299`, `317` | Native SQL should bind `selID`, `lastHistoryId`, and content IDs. |
| Password reset | `LoginController.java:232-278` | Endpoint lacks strong identity proof before sending password material. |
| Integration token | `LoginController.java:310-360` | Single API key is accepted without request signing, client identity, expiry, IP restriction, or scoped authorization. |

## 6. How the Enormity Sidecar Fixes the Query Vulnerabilities

The sidecar was implemented as a controlled, Enormity-owned read/report API under `/api/enormity/*`. Its query design is materially safer than the OEM controller query pattern.

### 6.1 Central query function uses parameter binding

**File:** `/opt/enormity-sidecar/server.js`  
**Lines:** 85-87

```js
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}
```

All sidecar database calls go through `pool.execute(sql, params)`, which sends parameters separately from SQL text.

### 6.2 Date input validation

**Lines:** 65-76

```js
if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
  const err = new Error('Invalid date format. Expected YYYY-MM-DD.');
  err.status = 400;
  throw err;
}
return [`${date} 00:00:00`, `${date} 23:59:59`];
```

This prevents arbitrary SQL fragments from being passed as date values.

### 6.3 Company filter uses bind parameter

**Lines:** 79-83

```js
function companyWhere(companyId, alias) {
  if (!companyId) return { clause: '', params: [] };
  const column = alias ? `${alias}.COMPANYID` : 'COMPANYID';
  return { clause: ` AND ${column} = ?`, params: [companyId] };
}
```

The only dynamic SQL fragment is an internally selected column name. The user-provided value is always appended to `params` and bound.

### 6.4 Patrol summary uses placeholders

**Lines:** 120-159

```js
WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`,
[start, end, ...company.params]
```

This replaces the OEM history pattern that directly concatenated `BeginTime`, `EndTime`, and department filters.

### 6.5 Guard efficiency, device status, heatmap, and KPM reports use placeholders

**Lines:** 232-249, 277-290, 307-319, 333-393

Examples:

```js
WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`,
[start, end, ...company.params]
```

```js
WHERE HAPPENTIME >= DATE_SUB(CURDATE(), INTERVAL ? DAY)${company.clause}`,
[days - 1, ...company.params]
```

```js
AND h.HAPPENTIME BETWEEN ? AND ?
WHERE r.DELETED = 0${companyId ? ' AND r.COMPANYID = ?' : ''}`,
companyId ? [start, end, companyId] : [start, end]
```

### 6.6 Report type allowlist

**Lines:** 333-337

```js
const supported = new Set(['pkk2', 'pkk3', 'pkk4']);
if (!supported.has(type)) {
  return fail(res, 400, "Invalid report type. Expected 'pkk2', 'pkk3', or 'pkk4'.");
}
```

This avoids using arbitrary client-provided report names to select SQL behavior.

## 7. OEM Java vs Enormity Sidecar Comparison

| Control area | OEM Java backend | Enormity Sidecar API |
|---|---|---|
| Query construction | Repeated JPQL/native SQL string concatenation using request parameters. | Uses `mysql2` `pool.execute(sql, params)` with bind parameters. |
| Date filters | Concatenated as quoted strings in JPQL/native SQL. | Validated as `YYYY-MM-DD`, expanded server-side to start/end timestamps, then bound. |
| Department/company filters | Often accepts comma-separated strings directly inside `IN (...)`. | Company filter value is bound with `?`; no arbitrary `IN (...)` strings currently exposed. |
| Report selection | Export endpoints pass raw `HttpServletRequest` into report services; service query behavior requires further audit. | Report type is allowlisted to `pkk2`, `pkk3`, `pkk4`. |
| Response format | Mixed `ResponseData`, binary exports, controller-specific formats. | Consistent `{ success, data, timestamp }` JSON shape. |
| Password handling | Decrypted password comparison; password reset emails current password. | Sidecar does not handle user passwords. |
| Integration auth | API key can mint admin token; quick integration decrypts user key and returns password in SSO object. | Sidecar currently has no password/token minting behavior; should add API key/JWT middleware before public use. |
| Data access | Broad OEM app database access with write endpoints. | Sidecar currently implements read/report endpoints only. |
| Auditability | Decompiled controller logic is hard to maintain and partially opaque through services. | In-house source is readable, versionable, and can be reviewed line-by-line. |

## 8. MySTI R&D Security Relevance

The security analysis supports the R&D claim that Enormity did not merely reskin the OEM system. The team performed reverse engineering, control-flow review, database schema analysis, and secure reimplementation of selected analytics/reporting APIs.

The sidecar represents original in-house engineering in these areas:

1. Security-oriented API redesign using parameterized SQL.
2. Consistent JSON API contract for analytics/report consumers.
3. Reduced dependence on unsafe OEM query assembly paths.
4. Separation of Enormity-owned `/api/enormity/*` namespace from OEM Java controllers.
5. Clear future path for authentication, authorization, logging, and rate limiting under Enormity control.

## 9. Recommended Remediation Roadmap

### Immediate controls

1. Add API-key or JWT middleware to `/opt/enormity-sidecar/server.js`.
2. Restrict `/api/enormity/*` in nginx by IP allowlist or bearer token until formal authentication is added.
3. Create a read-only MySQL user for the sidecar instead of using `root`.
4. Add nginx rate limiting for `/api/enormity/*`.
5. Store sidecar secrets outside repo-tracked files and rotate the exposed database and Telegram credentials.

### OEM-risk containment

1. Prefer sidecar endpoints for Enormity analytics/reporting instead of OEM report/history endpoints.
2. Avoid exposing OEM integration token endpoints publicly.
3. Review service-layer classes used by `ExportController`, especially `exportDataSearchService` and `customExportService`.
4. Add WAF/nginx rules to reject obvious SQL metacharacters in OEM query parameters where business-compatible.
5. Monitor `/history/getHistorydatas`, `/alarm*`, `/tour*`, `/export*`, and `/pdf*` for abnormal query strings.

### Long-term fixes

1. Replace OEM plaintext/reversible password flows with one-way password hashing.
2. Replace password reset by email with tokenized reset workflow.
3. Replace admin-token integration flow with scoped OAuth2/client credentials or signed API requests.
4. Refactor any retained Java endpoints to use named parameters or Criteria API.
5. Move more reporting/analytics workloads into the Enormity-owned sidecar layer.

## 10. Conclusion

The decompiled CloudPatrol backend contains multiple high-risk query construction patterns and critical authentication weaknesses. The most important SQL injection risks are in `HistoryController`, `AlarmdatasController`, `TourDataController`, `DashboardController`, and content/report-related paths. The most serious authentication concern is plaintext or reversible password handling, proven by password reset logic that emails the current stored password.

The Enormity Sidecar API addresses the query-injection class of vulnerability for Enormity-owned analytics/report endpoints by using parameterized MySQL queries, typed input validation, report type allowlisting, and a consistent API contract. For a government-facing MySTI submission, this demonstrates concrete R&D security work: reverse engineering, vulnerability analysis, secure API reimplementation, and a documented migration path away from unsafe OEM patterns.

The sidecar should be considered a security improvement layer, not a complete security boundary until API authentication, rate limiting, and read-only database credentials are added.
