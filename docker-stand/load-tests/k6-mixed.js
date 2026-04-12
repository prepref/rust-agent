import http from "k6/http";
import { sleep } from "k6";
import { loginToDvwa } from "./dvwa_auth.js";
import {
  BENIGN_AUTHENTICATED,
  GUEST,
  BAD_AUTHENTICATED,
  BAD_ANONYMOUS,
} from "./paths.js";

// Смесь: обычные запросы к DVWA + запросы с payload. Логин один раз (admin/password).
// Env: BASE_URL, BAD_RATIO, K6_VUS, K6_DURATION, DVWA_USER, DVWA_PASSWORD, SKIP_LOGIN=1

const BASE = (__ENV.BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const pBad = Math.min(1, Math.max(0, parseFloat(__ENV.BAD_RATIO || "0.15")));
const noLogin = __ENV.SKIP_LOGIN === "1";
const user = __ENV.DVWA_USER || "admin";
const pass = __ENV.DVWA_PASSWORD || "password";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0";
const H = { "User-Agent": UA };

export const options = {
  vus: parseInt(__ENV.K6_VUS || "5", 10),
  duration: __ENV.K6_DURATION || "2m",
};

let ok = false;
let tried = false;

export default function () {
  if (!noLogin && !tried) {
    tried = true;
    ok = loginToDvwa(BASE, user, pass, H);
  }

  const bad = Math.random() < pBad;
  const pool = ok
    ? bad
      ? BAD_AUTHENTICATED
      : BENIGN_AUTHENTICATED
    : bad
      ? BAD_ANONYMOUS
      : GUEST;
  const path = pool[Math.floor(Math.random() * pool.length)];

  const headers = {
    "User-Agent":
      bad && Math.random() < 0.3 ? "sqlmap/1.8.2#stable (http://sqlmap.org)" : UA,
  };
  http.get(`${BASE}${path}`, { headers });
  sleep(0.2 + Math.random() * 0.8);
}
