import http from "k6/http";
import { sleep } from "k6";
import { loginToDvwa } from "./dvwa_auth.js";
import { BENIGN_AUTHENTICATED, GUEST } from "./paths.js";

// Только обычные страницы DVWA. Env как в k6-mixed.js

const BASE = (__ENV.BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const noLogin = __ENV.SKIP_LOGIN === "1";
const user = __ENV.DVWA_USER || "admin";
const pass = __ENV.DVWA_PASSWORD || "password";
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36";
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

  const pool = ok ? BENIGN_AUTHENTICATED : GUEST;
  const path = pool[Math.floor(Math.random() * pool.length)];
  http.get(`${BASE}${path}`, { headers: H });
  sleep(0.3 + Math.random() * 0.9);
}
