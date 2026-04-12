import http from "k6/http";

// Логин admin/password → cookie для следующих запросов (нужна БД из setup.php).

function token(html) {
  const m =
    html.match(/name=["']user_token["']\s+value=["']([^"']+)["']/) ||
    html.match(/value=["']([^"']+)["']\s+name=["']user_token["']/);
  return m ? m[1] : "";
}

export function loginToDvwa(base, user, password, h) {
  const g = http.get(`${base}/login.php`, { headers: h });
  if (g.status !== 200) return false;

  let body = `username=${encodeURIComponent(user)}&password=${encodeURIComponent(password)}&Login=Login`;
  const t = token(g.body);
  if (t) body += `&user_token=${encodeURIComponent(t)}`;

  const postHeaders = Object.assign({}, h, {
    "Content-Type": "application/x-www-form-urlencoded",
  });
  http.post(`${base}/login.php`, body, { headers: postHeaders });

  const i = http.get(`${base}/index.php`, { headers: h });
  if (i.status !== 200) return false;
  return i.body.includes("Logout") || i.body.includes("logout.php");
}
