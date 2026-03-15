const HOSTING_PATTERN = /(Hosting|Cloud|Datacenter|VPN|Proxy|Infrastructure|Amazon|Google|Microsoft|DigitalOcean|Hetzner|OVH|Vultr|Oracle|Akamai|Fastly|Linode|Scaleway|Contabo|ColoCross|M247|GreenCloud|Tencent|Alibaba|LeaseWeb|Zscaler|Cloudflare|NordVPN|ExpressVPN|Surfshark|Mullvad|Private Internet|CyberGhost|TorGuard|IPVanish|HideMyAss|ProtonVPN|Windscribe)/i;
const MOBILE_PATTERN = /(Mobile|LTE|Cellular|Wireless|4G|5G|Telecommunication|Vodafone|Verizon|Orange|T-Mobile|EE|Three|O2|Sprint|Cricket|Boost|Metro|Visible)/i;
const EDUCATION_PATTERN = /(University|College|Education|School|Research|Academy|JANET|GÉANT|Internet2)/i;
const CORPORATE_PATTERN = /(Business|Enterprise|Corporation|Inc\.|Limited|Ltd\.|PLC|GmbH)/i;

function classifyISP(ispName) {
  if (HOSTING_PATTERN.test(ispName)) return "hosting";
  if (MOBILE_PATTERN.test(ispName)) return "mobile";
  if (EDUCATION_PATTERN.test(ispName)) return "education";
  if (CORPORATE_PATTERN.test(ispName)) return "corporate";
  return "residential";
}

const DATACENTER_ASNS = new Set([
  14061, 16509, 14618, 15169, 8075, 13335, 20473, 63949, 24940, 16276,
  51167, 197540, 9009, 46606, 36352, 55286, 62567, 398101, 206264, 142002,
  45102, 132203, 59930, 210644, 41378
]);

function fingerprintRequest(request) {
  const cf = request.cf || {};
  const ispName = cf.asOrganization || "unknown";
  return {
    tlsVersion: cf.tlsVersion || "unknown",
    httpProtocol: cf.httpProtocol || "unknown",
    asn: cf.asn || 0,
    asOrganization: ispName,
    ispType: classifyISP(ispName),
    country: cf.country || "unknown",
    city: cf.city || "unknown",
    colo: cf.colo || "unknown",
    headerCount: [...request.headers.keys()].length,
    hasAcceptLanguage: request.headers.has("accept-language"),
    hasAcceptEncoding: request.headers.has("accept-encoding"),
    hasSecFetchSite: request.headers.has("sec-fetch-site"),
    hasSecFetchMode: request.headers.has("sec-fetch-mode"),
    hasSecFetchDest: request.headers.has("sec-fetch-dest"),
    hasSecChUa: request.headers.has("sec-ch-ua"),
    hasSecChUaPlatform: request.headers.has("sec-ch-ua-platform"),
    hasSecChUaMobile: request.headers.has("sec-ch-ua-mobile"),
    acceptLanguage: request.headers.get("accept-language") || ""
  };
}

function calculateBotScore(fingerprint, userAgent) {
  let score = 0;
  const reasons = [];

  if (fingerprint.tlsVersion === "TLSv1.1" || fingerprint.tlsVersion === "TLSv1") {
    score += 30; reasons.push("old-tls");
  }
  if (fingerprint.httpProtocol === "HTTP/1.0") {
    score += 20; reasons.push("http1.0");
  }
  if (!userAgent || userAgent.length === 0) {
    score += 40; reasons.push("no-ua");
  } else if (userAgent.length < 20) {
    score += 15; reasons.push("short-ua");
  }
  if (userAgent && /Mozilla|Chrome|Safari|Firefox/.test(userAgent)) {
    if (!fingerprint.hasSecChUa && !fingerprint.hasSecFetchMode) {
      score += 20; reasons.push("fake-browser-ua");
    }
  }
  if (!fingerprint.hasAcceptLanguage) {
    score += 15; reasons.push("no-accept-lang");
  }
  if (!fingerprint.hasAcceptEncoding) {
    score += 10; reasons.push("no-accept-enc");
  }
  if (!fingerprint.hasSecFetchSite) { score += 5; reasons.push("no-sec-fetch-site"); }
  if (!fingerprint.hasSecFetchMode) { score += 5; reasons.push("no-sec-fetch-mode"); }
  if (!fingerprint.hasSecFetchDest) { score += 5; reasons.push("no-sec-fetch-dest"); }
  if (!fingerprint.hasSecChUa) { score += 5; reasons.push("no-sec-ch-ua"); }
  if (!fingerprint.hasSecChUaPlatform) { score += 3; reasons.push("no-sec-ch-ua-platform"); }
  if (!fingerprint.hasSecChUaMobile) { score += 3; reasons.push("no-sec-ch-ua-mobile"); }

  if (fingerprint.headerCount < 5) {
    score += 20; reasons.push("few-headers");
  } else if (fingerprint.headerCount < 8) {
    score += 10; reasons.push("low-headers");
  }

  if (fingerprint.ispType === "hosting") {
    score += 25; reasons.push("hosting-isp");
  } else if (fingerprint.ispType === "mobile") {
    score -= 5;
  } else if (fingerprint.ispType === "residential") {
    score -= 10;
  }

  if (fingerprint.ispType !== "hosting" && DATACENTER_ASNS.has(fingerprint.asn)) {
    score += 20; reasons.push("datacenter-asn");
  }

  if (fingerprint.hasAcceptLanguage) {
    const al = fingerprint.acceptLanguage;
    if (al && !al.includes(",") && !al.includes(";")) {
      score += 8; reasons.push("simple-accept-lang");
    }
  }

  return { score: Math.max(0, Math.min(score, 100)), reasons };
}

const SECURITY_HEADERS = {
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "interest-cohort=()",
  "Cache-Control": "no-store",
  "X-Robots-Tag": "noindex, nofollow"
};

const DECOY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>\u25C7</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{background:#0a0a0a;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:monospace}

.pattern{width:280px;height:280px;position:relative;margin-bottom:48px}

.pattern::before,.pattern::after{content:'';position:absolute;inset:0}

.pattern::before{
  background:
    linear-gradient(45deg,transparent 40%,#1a1a1a 40%,#1a1a1a 42%,transparent 42%),
    linear-gradient(-45deg,transparent 40%,#1a1a1a 40%,#1a1a1a 42%,transparent 42%),
    linear-gradient(45deg,transparent 58%,#1a1a1a 58%,#1a1a1a 60%,transparent 60%),
    linear-gradient(-45deg,transparent 58%,#1a1a1a 58%,#1a1a1a 60%,transparent 60%);
  background-size:60px 60px;
}

.pattern::after{
  background:
    linear-gradient(0deg,transparent 45%,#1a1a1a 45%,#1a1a1a 47%,transparent 47%),
    linear-gradient(90deg,transparent 45%,#1a1a1a 45%,#1a1a1a 47%,transparent 47%),
    linear-gradient(0deg,transparent 53%,#1a1a1a 53%,#1a1a1a 55%,transparent 55%),
    linear-gradient(90deg,transparent 53%,#1a1a1a 53%,#1a1a1a 55%,transparent 55%);
  background-size:60px 60px;
}

.geo{
  position:absolute;inset:0;
  background:
    radial-gradient(circle at 30px 30px,transparent 12px,#1a1a1a 12px,#1a1a1a 14px,transparent 14px),
    radial-gradient(circle at 0 0,transparent 12px,#1a1a1a 12px,#1a1a1a 14px,transparent 14px),
    radial-gradient(circle at 60px 0,transparent 12px,#1a1a1a 12px,#1a1a1a 14px,transparent 14px),
    radial-gradient(circle at 0 60px,transparent 12px,#1a1a1a 12px,#1a1a1a 14px,transparent 14px),
    radial-gradient(circle at 60px 60px,transparent 12px,#1a1a1a 12px,#1a1a1a 14px,transparent 14px);
  background-size:60px 60px;
}

.star{
  position:absolute;inset:0;
  background:
    conic-gradient(from 0deg at 30px 30px,
      transparent 0deg,transparent 30deg,#151515 30deg,#151515 32deg,
      transparent 32deg,transparent 58deg,#151515 58deg,#151515 60deg,
      transparent 60deg,transparent 120deg,#151515 120deg,#151515 122deg,
      transparent 122deg,transparent 148deg,#151515 148deg,#151515 150deg,
      transparent 150deg,transparent 210deg,#151515 210deg,#151515 212deg,
      transparent 212deg,transparent 238deg,#151515 238deg,#151515 240deg,
      transparent 240deg,transparent 300deg,#151515 300deg,#151515 302deg,
      transparent 302deg,transparent 328deg,#151515 328deg,#151515 330deg,
      transparent 330deg,transparent 360deg
    );
  background-size:60px 60px;
}

.frame{
  position:absolute;inset:0;
  border:1px solid #1a1a1a;
}

.frame::before{
  content:'';position:absolute;inset:8px;
  border:1px solid #151515;
}

.frame::after{
  content:'';position:absolute;inset:16px;
  border:1px solid #121212;
}

.msg{color:#333;font-size:14px;letter-spacing:4px;text-transform:lowercase}
.cursor{color:#333;font-size:18px;margin-top:12px;animation:blink 1.2s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
</style>
</head>
<body>
<div class="pattern">
  <div class="geo"></div>
  <div class="star"></div>
  <div class="frame"></div>
</div>
<div class="msg">curiosity is noted.</div>
<div class="cursor">&#9646;</div>
</body>
</html>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ua = request.headers.get("user-agent") || "";
    const fingerprint = fingerprintRequest(request);
    const botResult = calculateBotScore(fingerprint, ua);

    if (!/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|xml|json|txt)$/i.test(path)) {
      console.log({
        t: new Date().toISOString(),
        p: path,
        m: request.method,
        s: botResult.score,
        r: botResult.reasons,
        isp: fingerprint.ispType,
        asn: fingerprint.asn,
        org: fingerprint.asOrganization,
        co: fingerprint.country,
        ci: fingerprint.city,
        colo: fingerprint.colo,
        tls: fingerprint.tlsVersion,
        proto: fingerprint.httpProtocol,
        hc: fingerprint.headerCount,
        ua: ua.slice(0, 120)
      });
    }

    if (path === "/favicon.ico") {
      return new Response(null, { status: 204, headers: SECURITY_HEADERS });
    }

    return new Response(DECOY_HTML, {
      status: 200,
      headers: { ...SECURITY_HEADERS, "content-type": "text/html;charset=UTF-8" }
    });
  }
};
