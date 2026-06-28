"""
STRIDE Tehdit Modelleme Motoru
Bankacılık ağı bileşenleri için otomatik tehdit üretimi + risk skorlama
"""

# Her bileşen tipi için hangi STRIDE kategorilerinin geçerli olduğu
COMPONENT_STRIDE_MAP = {
    "web_portal": ["S", "T", "R", "I", "D", "E"],
    "api_gateway": ["S", "T", "R", "I", "D", "E"],
    "core_banking": ["S", "T", "R", "I", "D", "E"],
    "database": ["T", "I", "D"],
    "atm_network": ["S", "T", "I", "D", "E"],
    "admin_console": ["S", "T", "R", "I", "E"],
    "firewall": ["T", "D", "E"],
    "auth_server": ["S", "T", "R", "I", "E"],
    "message_queue": ["T", "I", "D"],
    "log_server": ["T", "R", "I"],
}

# STRIDE kategorisi açıklamaları
STRIDE_LABELS = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# Her bileşen + STRIDE kombinasyonu için hazır tehdit şablonları
THREAT_TEMPLATES = {
    ("web_portal", "S"): {
        "baslik": "Kimlik Sahteciliği — Müşteri Portalı",
        "aciklama": "Saldırgan, müşteri kimlik bilgilerini ele geçirerek portal oturumu açabilir.",
        "oneri": "Çok faktörlü kimlik doğrulama (MFA) ve CAPTCHA uygulanmalı.",
        "likelihood": 4, "impact": 5,
    },
    ("web_portal", "T"): {
        "baslik": "Veri Değiştirme — HTTP İsteği",
        "aciklama": "İstemci tarafından gönderilen form verileri değiştirilerek işlem tutarı manipüle edilebilir.",
        "oneri": "Sunucu tarafı doğrulama ve dijital imza zorunlu tutulmalı.",
        "likelihood": 3, "impact": 5,
    },
    ("web_portal", "R"): {
        "baslik": "İnkar Edilebilirlik — İşlem Kaydı",
        "aciklama": "Müşteri gerçekleştirdiği işlemi inkâr edebilir; yeterli denetim izi bulunmayabilir.",
        "oneri": "Tüm kritik işlemler zaman damgalı ve değiştirilemez log kaydına alınmalı.",
        "likelihood": 2, "impact": 4,
    },
    ("web_portal", "I"): {
        "baslik": "Bilgi Sızıntısı — Hata Mesajları",
        "aciklama": "Ayrıntılı hata mesajları sistem mimarisini veya hesap bilgilerini ifşa edebilir.",
        "oneri": "Üretim ortamında genel hata mesajları kullanılmalı; detay loglanmalı.",
        "likelihood": 3, "impact": 3,
    },
    ("web_portal", "D"): {
        "baslik": "Hizmet Reddi — DDoS Saldırısı",
        "aciklama": "Yoğun trafik ile portal erişilemez hale getirilebilir.",
        "oneri": "Rate limiting, CDN ve WAF kullanılmalı.",
        "likelihood": 3, "impact": 4,
    },
    ("web_portal", "E"): {
        "baslik": "Yetki Yükseltme — Hesap Ele Geçirme",
        "aciklama": "Normal kullanıcı, yönetici yetkisi gerektiren işlemlere erişim sağlayabilir.",
        "oneri": "Rol tabanlı erişim kontrolü (RBAC) ve en az yetki ilkesi uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("api_gateway", "S"): {
        "baslik": "Kimlik Sahteciliği — API Token Çalınması",
        "aciklama": "JWT/OAuth token'ları çalınarak API'ye yetkisiz erişim sağlanabilir.",
        "oneri": "Kısa ömürlü tokenlar, token rotation ve IP binding uygulanmalı.",
        "likelihood": 3, "impact": 5,
    },
    ("api_gateway", "T"): {
        "baslik": "Veri Değiştirme — API İstek Manipülasyonu",
        "aciklama": "API isteğindeki parametreler değiştirilerek farklı hesap verilerine erişilebilir.",
        "oneri": "İstek imzalama (HMAC) ve güçlü girdi doğrulama şart.",
        "likelihood": 3, "impact": 5,
    },
    ("api_gateway", "R"): {
        "baslik": "İnkar Edilebilirlik — API Çağrısı",
        "aciklama": "Hangi sistemin hangi API çağrısını yaptığı izlenemeyebilir.",
        "oneri": "Her API çağrısı kaynak IP + istemci ID ile loglanmalı.",
        "likelihood": 2, "impact": 3,
    },
    ("api_gateway", "I"): {
        "baslik": "Bilgi Sızıntısı — API Yanıtı",
        "aciklama": "API yanıtları hassas veri alanlarını gereğinden fazla döndürebilir.",
        "oneri": "Yanıt filtreleme (field masking) ve minimum veri ilkesi uygulanmalı.",
        "likelihood": 3, "impact": 4,
    },
    ("api_gateway", "D"): {
        "baslik": "Hizmet Reddi — API Flood",
        "aciklama": "Yüksek frekanslı API istekleriyle arka uç sistemleri çökertebilir.",
        "oneri": "Rate limiting, circuit breaker ve quota yönetimi uygulanmalı.",
        "likelihood": 4, "impact": 4,
    },
    ("api_gateway", "E"): {
        "baslik": "Yetki Yükseltme — Endpoint Atlatma",
        "aciklama": "Yetkilendirme kontrolü eksik endpoint'ler üzerinden yüksek yetkili işlem yapılabilir.",
        "oneri": "Her endpoint için bağımsız yetkilendirme kontrolü zorunlu.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "S"): {
        "baslik": "Kimlik Sahteciliği — İç Sistem Erişimi",
        "aciklama": "İç ağdan core banking sistemine sahte kimlikle bağlanılabilir.",
        "oneri": "Mutual TLS ve servis hesabı sertifika doğrulaması uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "T"): {
        "baslik": "Veri Değiştirme — Hesap Bakiyesi",
        "aciklama": "Veritabanı veya servis katmanında hesap bakiyesi izinsiz değiştirilebilir.",
        "oneri": "İşlem bütünlüğü kontrolleri, çift onay mekanizması ve denetim izi şart.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "R"): {
        "baslik": "İnkar Edilebilirlik — Finansal İşlem",
        "aciklama": "Gerçekleştirilen finansal işlem için yeterli kanıt bulunmayabilir.",
        "oneri": "Değiştirilemez audit log ve işlem imzalama sistemi kurulmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "I"): {
        "baslik": "Bilgi Sızıntısı — Müşteri Finansal Verisi",
        "aciklama": "Müşterilerin hesap hareketleri ve bakiye bilgileri yetkisiz kişilere sızabilir.",
        "oneri": "Veri şifreleme (at rest + in transit) ve erişim loglaması zorunlu.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "D"): {
        "baslik": "Hizmet Reddi — Core Sistem Çöküşü",
        "aciklama": "Core banking sisteminin çökmesi tüm banka operasyonlarını durdurabilir.",
        "oneri": "Yüksek erişilebilirlik (HA) mimarisi, yük dengeleme ve felaket kurtarma planı şart.",
        "likelihood": 2, "impact": 5,
    },
    ("core_banking", "E"): {
        "baslik": "Yetki Yükseltme — Operatör Yetkisi",
        "aciklama": "Düşük yetkili operatör, kritik finansal işlemleri tetikleyebilir.",
        "oneri": "4-göz ilkesi (maker-checker) ve ayrıştırılmış görev politikası uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("database", "T"): {
        "baslik": "Veri Değiştirme — SQL Enjeksiyonu",
        "aciklama": "Kötü niyetli SQL ifadeleri ile veritabanı kayıtları değiştirilebilir veya silinebilir.",
        "oneri": "Hazırlanmış ifadeler (prepared statements) ve ORM kullanımı zorunlu.",
        "likelihood": 3, "impact": 5,
    },
    ("database", "I"): {
        "baslik": "Bilgi Sızıntısı — Veritabanı Dökümü",
        "aciklama": "Tüm veritabanı yetkisiz kişiler tarafından dışarıya aktarılabilir.",
        "oneri": "Sütun düzeyinde şifreleme, VPN erişimi ve DB firewall kullanılmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("database", "D"): {
        "baslik": "Hizmet Reddi — Veritabanı Kilitleme",
        "aciklama": "Uzun süren sorgular veya bağlantı havuzu tüketimi DB'yi kilitleyebilir.",
        "oneri": "Sorgu zaman aşımı, bağlantı havuzu limitleri ve izleme alarmları tanımlanmalı.",
        "likelihood": 3, "impact": 4,
    },
    ("atm_network", "S"): {
        "baslik": "Kimlik Sahteciliği — Skimming Saldırısı",
        "aciklama": "ATM kart okuyucusuna yerleştirilen skimmer ile kart bilgileri çalınabilir.",
        "oneri": "Anti-skimming donanımı, EMV chip zorunluluğu ve fiziksel denetim periyotları.",
        "likelihood": 3, "impact": 4,
    },
    ("atm_network", "T"): {
        "baslik": "Veri Değiştirme — ATM Yazılım Manipülasyonu",
        "aciklama": "ATM yazılımı zararlı yazılımla değiştirilerek kart verisi ele geçirilebilir (jackpotting).",
        "oneri": "Uygulama beyaz listesi, güvenli önyükleme ve yazılım bütünlük doğrulaması şart.",
        "likelihood": 2, "impact": 5,
    },
    ("atm_network", "I"): {
        "baslik": "Bilgi Sızıntısı — PIN Yakalama",
        "aciklama": "PIN giriş trafiği şifresiz iletilirse saldırgan tarafından ele geçirilebilir.",
        "oneri": "Uçtan uca şifreleme (P2PE) ve HSM (Hardware Security Module) kullanımı şart.",
        "likelihood": 2, "impact": 5,
    },
    ("atm_network", "D"): {
        "baslik": "Hizmet Reddi — ATM Ağ Kesintisi",
        "aciklama": "ATM iletişim ağının kesilmesi nakit çekim hizmetini durdurabilir.",
        "oneri": "Yedekli bağlantı (4G failover) ve otomatik hata tespiti mekanizması.",
        "likelihood": 3, "impact": 3,
    },
    ("atm_network", "E"): {
        "baslik": "Yetki Yükseltme — Fiziksel Erişim",
        "aciklama": "ATM kasasına fiziksel erişim sağlayan saldırgan servis modunu kötüye kullanabilir.",
        "oneri": "Tamper-evident kapalı kutu, kamera izleme ve çift kilit mekanizması.",
        "likelihood": 2, "impact": 5,
    },
    ("admin_console", "S"): {
        "baslik": "Kimlik Sahteciliği — Yönetici Hesabı",
        "aciklama": "Yönetici kimlik bilgileri çalınarak tüm sistem yönetim yetkisi ele geçirilebilir.",
        "oneri": "Donanım MFA (YubiKey), ayrıcalıklı erişim yönetimi (PAM) zorunlu.",
        "likelihood": 2, "impact": 5,
    },
    ("admin_console", "T"): {
        "baslik": "Veri Değiştirme — Sistem Yapılandırması",
        "aciklama": "Güvenlik politikaları veya sistem parametreleri izinsiz değiştirilebilir.",
        "oneri": "Değişiklik yönetimi süreci, onay akışı ve otomatik drift tespiti.",
        "likelihood": 2, "impact": 5,
    },
    ("admin_console", "R"): {
        "baslik": "İnkar Edilebilirlik — Yönetici Eylemi",
        "aciklama": "Yönetici, gerçekleştirdiği kritik sistem eylemini inkâr edebilir.",
        "oneri": "Tüm admin eylemleri oturum kaydı (session recording) ile loglanmalı.",
        "likelihood": 2, "impact": 4,
    },
    ("admin_console", "I"): {
        "baslik": "Bilgi Sızıntısı — Sistem Yapılandırma Verisi",
        "aciklama": "Ağ topolojisi, IP adresleri ve güvenlik politikaları ifşa edilebilir.",
        "oneri": "Yapılandırma dosyaları şifreli saklanmalı; erişim kısıtlanmalı.",
        "likelihood": 2, "impact": 4,
    },
    ("admin_console", "E"): {
        "baslik": "Yetki Yükseltme — Privilege Escalation",
        "aciklama": "Düşük yetkili sistem kullanıcısı, yönetici paneline erişim sağlayabilir.",
        "oneri": "En az yetki ilkesi, just-in-time erişim ve PAM çözümü uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("firewall", "T"): {
        "baslik": "Veri Değiştirme — Firewall Kural Manipülasyonu",
        "aciklama": "Firewall kuralları değiştirilerek kritik sistemler dışarıya açılabilir.",
        "oneri": "Kural değişikliklerinde çift onay, versiyon kontrolü ve otomatik uyumlu uyarı.",
        "likelihood": 2, "impact": 5,
    },
    ("firewall", "D"): {
        "baslik": "Hizmet Reddi — Firewall Aşırı Yüklenmesi",
        "aciklama": "Yüksek trafik ile firewall işlem kapasitesi aşılarak ağ koruması devre dışı kalabilir.",
        "oneri": "Kapasiteye göre boyutlandırma, DDoS koruma servisi ve otomatik ölçekleme.",
        "likelihood": 3, "impact": 5,
    },
    ("firewall", "E"): {
        "baslik": "Yetki Yükseltme — Firewall Atlatma",
        "aciklama": "Tünelleme veya protokol manipülasyonuyla firewall kuralları atlatılabilir.",
        "oneri": "Derin paket incelemesi (DPI), uygulama katmanı filtreleme ve IPS entegrasyonu.",
        "likelihood": 2, "impact": 5,
    },
    ("auth_server", "S"): {
        "baslik": "Kimlik Sahteciliği — Sahte Kimlik Sunucusu",
        "aciklama": "DNS zehirlenmesiyle kullanıcılar sahte kimlik doğrulama sunucusuna yönlendirilebilir.",
        "oneri": "DNSSEC, sertifika sabitleme (certificate pinning) ve HSTS uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("auth_server", "T"): {
        "baslik": "Veri Değiştirme — Token İçeriği",
        "aciklama": "Zayıf imzalanmış token'lar değiştirilerek yetki kapsamı genişletilebilir.",
        "oneri": "RS256 veya ES256 algoritması, kısa TTL ve token revokasyon mekanizması.",
        "likelihood": 2, "impact": 5,
    },
    ("auth_server", "R"): {
        "baslik": "İnkar Edilebilirlik — Oturum Açma Kaydı",
        "aciklama": "Başarılı/başarısız giriş denemeleri yeterince loglanmıyor olabilir.",
        "oneri": "Her kimlik doğrulama olayı zaman, IP ve cihaz bilgisiyle loglanmalı.",
        "likelihood": 2, "impact": 3,
    },
    ("auth_server", "I"): {
        "baslik": "Bilgi Sızıntısı — Kullanıcı Adı Keşfi",
        "aciklama": "Hata mesajlarının farkı, geçerli kullanıcı adlarının tahmin edilmesine olanak tanır.",
        "oneri": "Tüm giriş hataları için aynı mesaj ve aynı gecikme süresi kullanılmalı.",
        "likelihood": 3, "impact": 3,
    },
    ("auth_server", "E"): {
        "baslik": "Yetki Yükseltme — Token Sahteciliği",
        "aciklama": "Token doğrulama zafiyeti ile saldırgan üst rol token'ı üretebilir.",
        "oneri": "Sunucu tarafı token doğrulama, claim kontrolü ve kara liste mekanizması.",
        "likelihood": 2, "impact": 5,
    },
    ("message_queue", "T"): {
        "baslik": "Veri Değiştirme — Mesaj Kuyruğu Manipülasyonu",
        "aciklama": "Kuyruktaki finansal mesajlar (transfer emirleri) değiştirilebilir.",
        "oneri": "Mesaj imzalama, şifreleme ve idempotency kontrolü uygulanmalı.",
        "likelihood": 2, "impact": 5,
    },
    ("message_queue", "I"): {
        "baslik": "Bilgi Sızıntısı — Kuyruk Dinleme",
        "aciklama": "Mesaj kuyruğuna yetkisiz abone olan kişi tüm trafiği izleyebilir.",
        "oneri": "Konu (topic) bazlı erişim kontrolü ve TLS şifreleme zorunlu.",
        "likelihood": 2, "impact": 4,
    },
    ("message_queue", "D"): {
        "baslik": "Hizmet Reddi — Kuyruk Dolması",
        "aciklama": "Kuyruğun aşırı dolması ile arka uç işleme durabilir.",
        "oneri": "Kuyruk boyutu limiti, dead-letter queue ve izleme alarmları tanımlanmalı.",
        "likelihood": 3, "impact": 4,
    },
    ("log_server", "T"): {
        "baslik": "Veri Değiştirme — Log Silme/Değiştirme",
        "aciklama": "Saldırgan izini kapatmak için log kayıtlarını silebilir veya değiştirebilir.",
        "oneri": "Merkezi, salt-okunur log sunucusu ve WORM depolama kullanılmalı.",
        "likelihood": 3, "impact": 5,
    },
    ("log_server", "R"): {
        "baslik": "İnkar Edilebilirlik — Eksik Log",
        "aciklama": "Kritik olaylar loglanmıyorsa saldırı sonrası soruşturma imkânsız hale gelir.",
        "oneri": "Log kapsamı politikası tanımlanmalı; boşluklar düzenli denetimle tespit edilmeli.",
        "likelihood": 2, "impact": 4,
    },
    ("log_server", "I"): {
        "baslik": "Bilgi Sızıntısı — Log Erişimi",
        "aciklama": "Log dosyaları müşteri verileri veya sistem mimarisini açığa çıkarabilir.",
        "oneri": "Log erişimi rol tabanlı kısıtlanmalı; hassas alanlar maskelenmeli.",
        "likelihood": 2, "impact": 4,
    },
}

RISK_LEVELS = [
    (20, "Kritik",   "#dc2626"),
    (15, "Yüksek",   "#ea580c"),
    (10, "Orta",     "#d97706"),
    (5,  "Düşük",    "#65a30d"),
    (0,  "Çok Düşük","#16a34a"),
]

COMPONENT_LABELS = {
    "web_portal":     "Müşteri Web Portalı",
    "api_gateway":    "API Gateway",
    "core_banking":   "Core Banking Sistemi",
    "database":       "Veritabanı Sunucusu",
    "atm_network":    "ATM Ağı",
    "admin_console":  "Yönetim Konsolu",
    "firewall":       "Güvenlik Duvarı",
    "auth_server":    "Kimlik Doğrulama Sunucusu",
    "message_queue":  "Mesaj Kuyruğu",
    "log_server":     "Log Sunucusu",
}


def risk_score(likelihood: int, impact: int) -> int:
    return likelihood * impact


def risk_level(score: int) -> tuple:
    for threshold, label, color in RISK_LEVELS:
        if score > threshold:
            return label, color
    return "Çok Düşük", "#16a34a"


def analyze_component(component_type: str) -> list:
    """Verilen bileşen tipi için tüm STRIDE tehditlerini üretir."""
    threats = []
    categories = COMPONENT_STRIDE_MAP.get(component_type, [])
    for cat in categories:
        key = (component_type, cat)
        template = THREAT_TEMPLATES.get(key)
        if not template:
            continue
        score = risk_score(template["likelihood"], template["impact"])
        level, color = risk_level(score)
        threats.append({
            "stride_kodu": cat,
            "stride_adi": STRIDE_LABELS[cat],
            "baslik": template["baslik"],
            "aciklama": template["aciklama"],
            "oneri": template["oneri"],
            "likelihood": template["likelihood"],
            "impact": template["impact"],
            "risk_skoru": score,
            "risk_seviyesi": level,
            "risk_rengi": color,
        })
    threats.sort(key=lambda x: x["risk_skoru"], reverse=True)
    return threats


def analyze_model(components: list) -> dict:
    """
    components: [{"id": "...", "tip": "web_portal", "isim": "Müşteri Portalı"}, ...]
    Tüm bileşenler için tehdit analizi yapar ve özet istatistik döner.
    """
    results = []
    total_threats = 0
    severity_counts = {"Kritik": 0, "Yüksek": 0, "Orta": 0, "Düşük": 0, "Çok Düşük": 0}

    for comp in components:
        threats = analyze_component(comp["tip"])
        total_threats += len(threats)
        for t in threats:
            sev = t["risk_seviyesi"]
            if sev in severity_counts:
                severity_counts[sev] += 1
        results.append({
            "id": comp["id"],
            "isim": comp.get("isim", COMPONENT_LABELS.get(comp["tip"], comp["tip"])),
            "tip": comp["tip"],
            "tip_label": COMPONENT_LABELS.get(comp["tip"], comp["tip"]),
            "tehditler": threats,
            "tehdit_sayisi": len(threats),
            "en_yuksek_risk": threats[0]["risk_skoru"] if threats else 0,
        })

    results.sort(key=lambda x: x["en_yuksek_risk"], reverse=True)

    return {
        "bilesenler": results,
        "toplam_tehdit": total_threats,
        "onem_dagılımı": severity_counts,
        "genel_risk": _genel_risk(severity_counts),
    }


def _genel_risk(counts: dict) -> str:
    if counts["Kritik"] > 0:
        return "Kritik"
    if counts["Yüksek"] > 2:
        return "Yüksek"
    if counts["Orta"] > 3:
        return "Orta"
    return "Düşük"
