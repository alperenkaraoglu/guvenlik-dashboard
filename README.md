#  Security Dashboard & Domain Security Analyzer

FastAPI tabanlı, alan adlarının (domain) güvenlik yapılandırmalarını ve DNS/IP kayıtlarını analiz eden hafif ve hızlı bir web uygulaması.

##  Özellikler

* **DNS & IP Analizi:** Hedef alan adının IP adreslerini ve temel DNS kayıtlarını sorgular.
* **Security Headers Analizi:** HSTS, CSP, X-Frame-Options gibi kritik web güvenlik başlıklarının varlığını denetler.
* **Modern Arayüz:** HTML/JS tabanlı, kullanımı kolay ve hızlı kullanıcı arayüzü.
* **Docker Desteği:** Konteyner mimarisi (Containerization) sayesinde tek komutla her ortamda sorunsuz çalışır.

##  Kullanılan Teknolojiler

* **Backend:** Python 3.11, FastAPI, Uvicorn
* **Frontend:** HTML5, CSS3, JavaScript (Fetch API)
* **DevOps & Dağıtım:** Docker, docker-compose, Git, Render.com

##  Hızlı Başlangıç

### Yöntem 1: Docker ile Çalıştırma (Önerilen)

Sisteminizde Docker yüklüyse, projeyi klonlayıp tek komutla başlatabilirsiniz:

```bash
git clone [https://github.com/KULLANICI_ADIN/guvenlik-dashboard.git](https://github.com/KULLANICI_ADIN/guvenlik-dashboard.git)
cd guvenlik-dashboard
docker-compose up -d
