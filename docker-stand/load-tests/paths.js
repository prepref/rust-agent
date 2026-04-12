// Общие пути для k6 (образ vulnerables/web-dvwa / классический DVWA).
// «Безопасные» — обычный просмотр / id=1 / короткий текст без payload.

export const BENIGN_AUTHENTICATED = [
  "/index.php",
  "/instructions.php",
  "/security.php",
  "/about.php",
  "/vulnerabilities/sqli/?id=1&Submit=Submit",
  "/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
  "/vulnerabilities/xss_r/?name=Alice",
  "/vulnerabilities/xss_s/?txt=hello",
  "/vulnerabilities/csrf/",
  "/vulnerabilities/fi/?page=include.php",
  "/vulnerabilities/upload/",
  "/vulnerabilities/exec/",
  "/vulnerabilities/brute/",
  "/vulnerabilities/csp/",
  "/vulnerabilities/javascript/",
  "/vulnerabilities/open_redirect/",
];

export const GUEST = [
  "/",
  "/login.php",
  "/setup.php",
  "/instructions.php",
  "/about.php",
];

export const BAD_AUTHENTICATED = [
  "/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit",
  "/vulnerabilities/sqli_blind/?id=1%27+OR+1%3D1--&Submit=Submit",
  "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
  "/vulnerabilities/xss_s/?txt=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
  "/vulnerabilities/fi/?page=..%2F..%2F..%2Fetc%2Fpasswd",
  "/vulnerabilities/exec/?ip=127.0.0.1%3B+cat+%2Fetc%2Fpasswd",
];

export const BAD_ANONYMOUS = [
  "/vulnerabilities/sqli/?id=1%27+OR+1%3D1--&Submit=Submit",
  "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
  "/vulnerabilities/fi/?page=..%2F..%2Fetc%2Fpasswd",
];
