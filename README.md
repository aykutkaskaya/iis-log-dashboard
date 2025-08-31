# IIS Log Dashboard (Streamlit)

📊 Basit ve kullanıcı dostu bir **IIS Log Analiz Dashboard’u**.  
Bu uygulama ile tek bir IIS W3C log dosyasını (`.log` veya `.txt`) yükleyebilir, trafik, hata kodları, yanıt süreleri ve IP dağılımlarını kolayca analiz edebilirsiniz.

---

## 🚀 Özellikler
- **Tek dosya upload desteği** (klasör bağlama gerekmez)  
- Genel trafik özeti (istek sayısı, gün sayısı, IP sayısı, hata oranı, P95/P99 süreler)  
- **Zaman bazlı analizler**  
  - Saatlik trafik  
  - Günlük trafik  
- **HTTP durum kodları ve hata analizi** (404/500 en çok görülen sayfalar)  
- **Performans analizi** (yanıt süreleri histogramı, en yavaş & en hızlı sayfalar)  
- **IP adresleri** (en aktif IP listesi)  
- Kolay **CSV dışa aktarım**  
- Farklı **renk paletleri** ve **zaman dilimi** seçimi  

---

## 📦 Kurulum

### 1. Kaynak Kod ile Çalıştırma
```bash
git clone https://github.com/kullaniciadi/iis-log-dashboard.git
cd iis-log-dashboard

# Sanal ortam (opsiyonel ama tavsiye edilir)
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Gereksinimleri yükle
pip install -r requirements.txt

# Çalıştır
streamlit run app.py
```

👉 Aç: [http://localhost:8501](http://localhost:8501)

---

### 2. Docker ile Çalıştırma
```bash
# İmaj oluştur
docker build -t iis-dashboard .

# Container başlat
docker run -d -p 8501:8501 --name iis-dashboard iis-dashboard
```

👉 Aç: [http://localhost:8501](http://localhost:8501)

---

## 📂 Kullanım
1. Web arayüzünden **tek bir log dosyası** (`.log` veya `.txt`) seçin.  
2. Filtreleri (tarih, durum kodu, HTTP metod) uygulayın.  
3. Grafik ve tablolarla trafiği analiz edin.  
4. Sonuçları **CSV** olarak indirin.

---

## 🛠 Gereksinimler
- Python 3.9+  
- [Streamlit](https://streamlit.io/)  
- pandas, plotly, pytz, user-agents  

---

## 📜 Lisans
MIT  
