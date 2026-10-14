"""
Domain Güvenlik Analiz API'si
==============================
Kullanıcının girdiği bir domain adresini analiz ederek:
  1. SSL/TLS sertifika bilgilerini
  2. HTTP güvenlik başlıklarını ve güvenlik skorunu
döndüren bir FastAPI uygulaması.
"""

import ssl
import socket
import datetime
from typing import Any

import requests
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse

# ── FastAPI uygulama tanımı ──────────────────────────────────────────────────
app = FastAPI(
    title="Domain Güvenlik Analiz API",
    description="Bir domain adresinin SSL sertifikasını ve HTTP güvenlik başlıklarını analiz eder.",
    version="1.0.0",
)


# ═══════════════════════════════════════════════════════════════════════════════
# YARDIMCI FONKSİYONLAR
# ═══════════════════════════════════════════════════════════════════════════════

def _clean_domain(domain: str) -> str:
    """Kullanıcıdan gelen domain'i temizle (protokol, eğik çizgi vb. kaldır)."""
    domain = domain.strip()
    for prefix in ("https://", "http://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/").split("/")[0]


def _get_ssl_certificate(domain: str, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    """
    Verilen domain:port adresine SSL bağlantısı açarak sertifika bilgilerini döndürür.
    """
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            # Sertifika zinciri (DER formatında) – ham veri
            cert_der = ssock.getpeercert(binary_form=True)
            protocol_version = ssock.version()
            cipher = ssock.cipher()
    return {
        "parsed": cert,
        "der_length_bytes": len(cert_der) if cert_der else 0,
        "protocol_version": protocol_version,
        "cipher": cipher,
    }


def _parse_cert_date(date_str: str) -> datetime.datetime:
    """OpenSSL tarih formatını datetime objesine çevir."""
    # Örn: 'Sep 15 00:00:00 2025 GMT'
    return datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")


def _format_issuer(issuer_tuples: tuple) -> dict[str, str]:
    """Sertifika issuer bilgisini düzleştirilmiş sözlük olarak döndür."""
    result: dict[str, str] = {}
    for entry in issuer_tuples:
        for key, value in entry:
            result[key] = value
    return result


def _format_subject(subject_tuples: tuple) -> dict[str, str]:
    """Sertifika subject bilgisini düzleştirilmiş sözlük olarak döndür."""
    result: dict[str, str] = {}
    for entry in subject_tuples:
        for key, value in entry:
            result[key] = value
    return result


def _extract_san(cert: dict) -> list[str]:
    """Subject Alternative Names listesini çıkar."""
    san = cert.get("subjectAltName", ())
    return [value for _type, value in san]


# ═══════════════════════════════════════════════════════════════════════════════
# GÜVENLİK BAŞLIKLARI & SKORLAMA
# ═══════════════════════════════════════════════════════════════════════════════

# Kontrol edilecek kritik güvenlik başlıkları ve ağırlıkları (toplam 100)
SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "weight": 30,
        "description": "HTTPS zorunluluğunu tarayıcıya bildirir (HSTS).",
    },
    "Content-Security-Policy": {
        "weight": 30,
        "description": "XSS ve veri enjeksiyonu saldırılarına karşı içerik politikası tanımlar.",
    },
    "X-Frame-Options": {
        "weight": 20,
        "description": "Clickjacking saldırılarına karşı koruma sağlar.",
    },
    "X-Content-Type-Options": {
        "weight": 20,
        "description": "MIME-type sniffing saldırılarına karşı koruma sağlar.",
    },
}


def _fetch_headers(domain: str, timeout: int = 10) -> tuple[dict[str, str], str]:
    """Domain'e HTTPS (yoksa HTTP) isteği atarak response header'larını döndürür."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            # Header anahtarlarını orijinal haliyle koru
            headers = dict(resp.headers)
            return headers, resp.url
        except requests.RequestException:
            continue
    raise ConnectionError(f"{domain} adresine HTTP/HTTPS ile ulaşılamadı.")


def _calculate_security_score(
    headers: dict[str, str],
) -> tuple[int, list[dict[str, Any]]]:
    """
    Güvenlik başlıklarını kontrol ederek 0-100 arası bir skor ve
    başlık bazında detay listesi döndürür.
    """
    # Header lookup için case-insensitive arama (anahtarları küçük harfe çevir)
    lower_headers = {k.lower(): v for k, v in headers.items()}

    score = 0
    details: list[dict[str, Any]] = []

    for header_name, meta in SECURITY_HEADERS.items():
        present = header_name.lower() in lower_headers
        value = lower_headers.get(header_name.lower(), None)
        if present:
            score += meta["weight"]
        details.append(
            {
                "header": header_name,
                "present": present,
                "value": value,
                "weight": meta["weight"],
                "description": meta["description"],
                "status": "[OK] Mevcut" if present else "[X] Eksik",
            }
        )

    return score, details


# ═══════════════════════════════════════════════════════════════════════════════
# API UÇLARI (ENDPOINTS)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def root():
    """Ana sayfa – Security Dashboard arayüzünü sun."""
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"), status_code=200)


# ── 1) SSL/TLS Sertifika Analizi ─────────────────────────────────────────────
@app.get("/api/ssl")
def ssl_analysis(
    domain: str = Query(..., description="Analiz edilecek domain adresi (örn: google.com)"),
):
    """
    Verilen domain'in SSL/TLS sertifikasını analiz eder.
    Bitiş tarihi, kalan gün sayısı, yayınlayan kurum ve geçerlilik durumunu döndürür.
    """
    domain = _clean_domain(domain)

    try:
        cert_data = _get_ssl_certificate(domain)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"SSL bağlantısı kurulamadı: {exc}",
        )

    cert = cert_data["parsed"]
    not_before = _parse_cert_date(cert["notBefore"])
    not_after = _parse_cert_date(cert["notAfter"])
    now = datetime.datetime.utcnow()
    days_remaining = (not_after - now).days
    is_valid = now >= not_before and now <= not_after

    issuer = _format_issuer(cert.get("issuer", ()))
    subject = _format_subject(cert.get("subject", ()))
    san_list = _extract_san(cert)

    return {
        "domain": domain,
        "summary": {
            "is_valid": is_valid,
            "days_remaining": days_remaining,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "issuer_organization": issuer.get("organizationName", "N/A"),
            "issuer_common_name": issuer.get("commonName", "N/A"),
            "subject_common_name": subject.get("commonName", "N/A"),
        },
        "connection": {
            "protocol_version": cert_data["protocol_version"],
            "cipher_suite": cert_data["cipher"][0] if cert_data["cipher"] else None,
            "cipher_bits": cert_data["cipher"][2] if cert_data["cipher"] else None,
        },
        "raw_certificate": {
            "issuer": issuer,
            "subject": subject,
            "subject_alt_names": san_list,
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "ocsp": cert.get("OCSP", []),
            "ca_issuers": cert.get("caIssuers", []),
            "der_size_bytes": cert_data["der_length_bytes"],
        },
    }


# ── 2) HTTP Güvenlik Başlıkları & Skorlama ───────────────────────────────────
@app.get("/api/headers")
def headers_analysis(
    domain: str = Query(..., description="Analiz edilecek domain adresi (örn: google.com)"),
):
    """
    Verilen domain'in HTTP güvenlik başlıklarını kontrol eder ve
    0-100 arası bir güvenlik skoru hesaplar.
    """
    domain = _clean_domain(domain)

    try:
        raw_headers, final_url = _fetch_headers(domain)
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"HTTP isteği başarısız: {exc}",
        )

    score, header_details = _calculate_security_score(raw_headers)

    present_count = sum(1 for h in header_details if h["present"])
    total_count = len(header_details)

    return {
        "domain": domain,
        "final_url": final_url,
        "summary": {
            "security_score": score,
            "max_score": 100,
            "grade": (
                "A+" if score == 100
                else "A" if score >= 80
                else "B" if score >= 60
                else "C" if score >= 40
                else "D" if score >= 20
                else "F"
            ),
            "headers_present": f"{present_count}/{total_count}",
        },
        "header_analysis": header_details,
        "raw_headers": raw_headers,
    }


# ── 3) Tam Analiz (iki endpoint'in birleşimi) ────────────────────────────────
@app.get("/api/analyze")
def full_analysis(
    domain: str = Query(..., description="Analiz edilecek domain adresi (örn: google.com)"),
):
    """
    SSL sertifika analizi ve HTTP güvenlik başlıkları analizini
    tek bir JSON yanıtında birleştirir.
    """
    ssl_result: dict[str, Any] | None = None
    ssl_error: str | None = None
    headers_result: dict[str, Any] | None = None
    headers_error: str | None = None

    # SSL analizi
    try:
        ssl_result = ssl_analysis(domain=domain)
    except HTTPException as exc:
        ssl_error = exc.detail

    # Header analizi
    try:
        headers_result = headers_analysis(domain=domain)
    except HTTPException as exc:
        headers_error = exc.detail

    clean = _clean_domain(domain)

    return {
        "domain": clean,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "ssl_analysis": ssl_result if ssl_result else {"error": ssl_error},
        "headers_analysis": headers_result if headers_result else {"error": headers_error},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SUNUCU BAŞLATMA
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn

    print("[*] Domain Guvenlik Analiz API'si baslatiliyor...")
    print("[+] Swagger UI: http://127.0.0.1:8000/docs")
    print("[+] ReDoc:      http://127.0.0.1:8000/redoc")
    uvicorn.run(app, host="0.0.0.0", port=8000)
