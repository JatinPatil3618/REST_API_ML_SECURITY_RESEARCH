"""Catalog still exposes the original mitigation strings plus executable techniques."""

from mitigations import describe


def check(cond, msg):
    if not cond:
        raise SystemExit(msg)


def main():
    sql = describe("SQL Injection")
    check(sql["mitigation"] == "BLOCK + parameterized query path", sql)
    check("hard_block" in sql["techniques"], sql)
    check("no_sql_execution" in sql["techniques"], sql)
    cookie = describe("Cookie Injection")
    check(cookie["mitigation"] == "BLOCK + session validation", cookie)
    check("invalidate_session_cookie" in cookie["techniques"], cookie)
    bola = describe("BOLA")
    check(bola["mitigation"] == "BLOCK + authorization", bola)
    check("backend_owner_check" in bola["techniques"], bola)
    allow = describe("BENIGN")
    check(allow["mitigation"] == "ALLOW", allow)
    print("mitigation catalog checks passed")


if __name__ == "__main__":
    main()
