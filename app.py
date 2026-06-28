"""
STRIDE Tehdit Modelleme Aracı — Flask Web Uygulaması
Bankacılık ağı bileşenleri için interaktif STRIDE analizi
"""

from flask import Flask, render_template, request, jsonify, session
import json
import uuid
import os
from datetime import datetime
from stride_engine import (
    analyze_model,
    analyze_component,
    COMPONENT_LABELS,
    COMPONENT_STRIDE_MAP,
    STRIDE_LABELS,
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

GECMIS_DOSYA = "data/model_history.json"


def gecmis_yukle():
    if os.path.exists(GECMIS_DOSYA):
        with open(GECMIS_DOSYA, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def gecmis_kaydet(kayit):
    gecmis = gecmis_yukle()
    gecmis.insert(0, kayit)
    gecmis = gecmis[:20]  # son 20 model
    with open(GECMIS_DOSYA, "w", encoding="utf-8") as f:
        json.dump(gecmis, f, ensure_ascii=False, indent=2)


@app.route("/")
def index():
    return render_template(
        "index.html",
        component_labels=COMPONENT_LABELS,
        stride_labels=STRIDE_LABELS,
    )


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    components = data.get("components", [])
    model_adi = data.get("model_adi", "İsimsiz Model")

    if not components:
        return jsonify({"hata": "En az bir bileşen seçilmeli."}), 400

    sonuc = analyze_model(components)
    sonuc["model_adi"] = model_adi
    sonuc["analiz_tarihi"] = datetime.now().strftime("%d.%m.%Y %H:%M")
    sonuc["model_id"] = str(uuid.uuid4())[:8]

    # Geçmişe kaydet (tehdit detayları hariç — özet)
    ozet = {
        "model_id": sonuc["model_id"],
        "model_adi": model_adi,
        "tarih": sonuc["analiz_tarihi"],
        "bilesen_sayisi": len(components),
        "toplam_tehdit": sonuc["toplam_tehdit"],
        "genel_risk": sonuc["genel_risk"],
        "components": components,
    }
    gecmis_kaydet(ozet)

    return jsonify(sonuc)


@app.route("/api/component/<tip>")
def component_threats(tip):
    from stride_engine import COMPONENT_LABELS
    if tip not in COMPONENT_STRIDE_MAP:
        return jsonify({"hata": "Bilinmeyen bileşen tipi."}), 404
    tehditler = analyze_component(tip)
    return jsonify({
        "tip": tip,
        "label": COMPONENT_LABELS.get(tip, tip),
        "tehditler": tehditler,
    })


@app.route("/gecmis")
def gecmis():
    kayitlar = gecmis_yukle()
    return render_template("gecmis.html", kayitlar=kayitlar)


@app.route("/api/gecmis")
def api_gecmis():
    return jsonify(gecmis_yukle())


@app.route("/hakkinda")
def hakkinda():
    return render_template("hakkinda.html")


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    print("STRIDE Tehdit Modelleme Aracı başlatılıyor...")
    print("Adres: http://127.0.0.1:5060")
    app.run(debug=True, host="127.0.0.1", port=5060)
