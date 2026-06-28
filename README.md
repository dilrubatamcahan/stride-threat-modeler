# STRIDE Tehdit Modelleme Aracı

Bankacılık ağı bileşenlerine yönelik otomatik STRIDE tehdit analizi ve risk skorlama aracı.

## Özellikler

- 10 bankacılık ağı bileşeni (Web Portalı, Core Banking, ATM, API Gateway vb.)
- Her bileşen için otomatik STRIDE tehdit üretimi (toplam 46 tehdit şablonu)
- Olasılık × Etki formülüyle risk skorlama (1–25)
- Renk kodlu tehdit kartları ve önem dağılımı grafikleri
- Analiz geçmişi (son 20 model)
- JSON export

## Kurulum ve Çalıştırma

```powershell
cd "C:\Users\DİLRUBA\OneDrive\Desktop\stride-threat-modeler"
pip install -r requirements.txt
python -X utf8 app.py
```

Tarayıcıda aç: http://127.0.0.1:5060

## Testler

```powershell
python -X utf8 -m pytest tests/ -v
# 28/28 PASSED
```

## STRIDE Metodolojisi

| Harf | Tehdit | Açıklama |
|------|--------|----------|
| S | Spoofing | Kimlik sahteciliği |
| T | Tampering | Veri değiştirme |
| R | Repudiation | İnkar edilebilirlik |
| I | Information Disclosure | Bilgi sızıntısı |
| D | Denial of Service | Hizmet reddi |
| E | Elevation of Privilege | Yetki yükseltme |

## Risk Seviyeleri

| Skor | Seviye |
|------|--------|
| 21–25 | Kritik |
| 16–20 | Yüksek |
| 11–15 | Orta |
| 6–10 | Düşük |
| 1–5 | Çok Düşük |

## Teknik Stack

- **Backend:** Python 3.x, Flask
- **Motor:** stride_engine.py (kural tabanlı, 46 tehdit şablonu)
- **Frontend:** Vanilla JS, CSS Grid
- **Test:** pytest — 28 birim testi

## Proje Yapısı

```
stride-threat-modeler/
├── app.py                 # Flask web uygulaması
├── stride_engine.py       # STRIDE analiz motoru
├── requirements.txt
├── templates/
│   ├── base.html
│   ├── index.html         # Model oluşturma sayfası
│   ├── gecmis.html        # Analiz geçmişi
│   └── hakkinda.html      # Proje bilgisi
├── static/
│   ├── css/style.css
│   └── js/app.js
├── data/
│   └── model_history.json # Analiz geçmişi (otomatik oluşur)
└── tests/
    └── test_stride_engine.py
```

