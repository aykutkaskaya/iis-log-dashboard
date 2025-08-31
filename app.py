import streamlit as st
import pandas as pd
import plotly.express as px
import os
import glob
import socket
import folium
from streamlit_folium import folium_static
import user_agents
from pytz import timezone
import io
from typing import Optional, List  # ✅ PY3.9 uyum için eklendi

# ------------------------------
# Yardımcı: Türetilmiş tablolarda kolon boşluğu sorununa çözüm
def safe_view(df_in: pd.DataFrame, preferred_cols: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Türetilmiş tablolarda show_cols kesişiminden dolayı boş görünmeyi önler.
    preferred_cols verilirse ve mevcutsa onları döndürür; aksi halde df_in'i olduğu gibi döndürür.
    """
    if df_in is None or df_in.empty:
        return df_in
    if preferred_cols:
        exist = [c for c in preferred_cols if c in df_in.columns]
        if exist:
            return df_in[exist]
    return df_in
# ------------------------------

# Sayfa ayarları
st.set_page_config(layout="wide")
st.title("📊 IIS Log Dashboard")

# 🎨 Renk paleti seçimi
palette_options = {
    "Turbo": px.colors.sequential.Turbo,
    "Set2": px.colors.qualitative.Set2,
    "Bold": px.colors.qualitative.Bold,
    "Pastel": px.colors.qualitative.Pastel
}
selected_palette = st.sidebar.selectbox("🎨 Renk Paleti Seç", list(palette_options.keys()), index=0)
colors = palette_options[selected_palette]
st.session_state['palette'] = selected_palette  # yalnızca görselleştirmeleri etkilesin

# Session state'i başlat
if 'df' not in st.session_state:
    st.session_state.df = pd.DataFrame()

st.sidebar.header("📁 Veri Yükleme")
log_source = st.sidebar.radio("Log kaynağını seçin:", ["Klasör", "Tek dosya"])

# Klasör veya dosya seçim alanı
if log_source == "Klasör":
    folder = st.sidebar.text_input("Klasör yolu girin:", key='folder_input')
    uploaded_file = None
else:
    uploaded_file = st.sidebar.file_uploader("Log dosyasını seçin", type=["log", "txt"], key='file_uploader')
    folder = None

resolve_hostnames = st.sidebar.checkbox("Hostname'leri Çözümle", value=False)
resolve_geo_ip = st.sidebar.checkbox("Coğrafi Konumları Çözümle (Harita)", value=False)

# Zaman Dilimi Seçimi
timezone_options = ['UTC', 'Europe/Istanbul', 'America/New_York', 'Asia/Tokyo']
selected_timezone = st.sidebar.selectbox("Zaman Dilimi Seç", timezone_options, index=1)

# Analiz başlatma butonu
run_analysis_button = st.sidebar.button("Analiz Et")

# "Veriyi Temizle" butonu
clear_data_button = st.sidebar.button("Veriyi Temizle")
if clear_data_button:
    if 'df' in st.session_state:
        del st.session_state.df
    st.success("Log verileri temizlendi.")
    st.experimental_rerun()

# Hostname çözümleme fonksiyonu
@st.cache_data(show_spinner=False)
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, Exception):
        return "Bilinmiyor"

# Geo-IP çözümleme fonksiyonu
@st.cache_data(show_spinner=False)
def get_geo_location(ip):
    try:
        import requests
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=4)
        data = response.json()
        if 'loc' in data:
            lat, lon = data['loc'].split(',')
            return float(lat), float(lon), data.get('country', 'Bilinmiyor')
    except Exception:
        pass
    return None, None, "Bilinmiyor"

# Klasör için cache anahtarı
@st.cache_data(show_spinner=False)
def _cache_key_for_folder(folder_path):
    infos = []
    for p in glob.glob(os.path.join(folder_path, "*.log")):
        try:
            infos.append((os.path.basename(p), os.path.getmtime(p)))
        except:
            pass
    return hash(tuple(infos))

# Klasörden log yükleme (parsing)
def load_logs_from_folder(folder_path):
    all_logs = []
    file_list = glob.glob(os.path.join(folder_path, "*.log"))
    total = len(file_list)
    progress_bar = st.sidebar.progress(0, text="⏳ Loglar yükleniyor...")
    for i, file in enumerate(file_list):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "#Fields:" not in content:
                    continue
                lines = content.split("\n")
                fields = []
                data = []
                for line in lines:
                    if line.startswith("#Fields:"):
                        fields = line[9:].strip().split()
                    elif not line.startswith("#") and line.strip() != "":
                        row = line.split()
                        if len(row) == len(fields):
                            data.append(row)
                if data:
                    df = pd.DataFrame(data, columns=fields)
                    all_logs.append(df)
        except Exception as e:
            st.error(f"Hata: {file} dosyası yüklenemedi. Sebep: {e}")
        progress_bar.progress((i + 1) / total, text=f"⏳ Yükleniyor ({i+1}/{total})")
    progress_bar.empty()
    return pd.concat(all_logs, ignore_index=True) if all_logs else pd.DataFrame()

# Parquet ara bellekli yükleme
def load_logs_from_folder_cached(folder_path):
    key = _cache_key_for_folder(folder_path)
    cache_parquet = os.path.join(folder_path, f"._iis_cache_{key}.parquet")
    if os.path.exists(cache_parquet):
        try:
            return pd.read_parquet(cache_parquet)
        except Exception:
            pass
    df = load_logs_from_folder(folder_path)
    if not df.empty:
        try:
            df.to_parquet(cache_parquet, index=False)
        except Exception:
            pass
    return df

def load_log_file(uploaded_file):
    try:
        content = uploaded_file.getvalue().decode("utf-8", errors="ignore")
        lines = content.split("\n")
        fields = []
        data = []
        for line in lines:
            if line.startswith("#Fields:"):
                fields = line[9:].strip().split()
            elif not line.startswith("#") and line.strip() != "":
                row = line.split()
                if len(row) == len(fields):
                    data.append(row)
        return pd.DataFrame(data, columns=fields) if data else pd.DataFrame()
    except Exception as e:
        st.error(f"Hata: Dosya yüklenemedi. Sebep: {e}")
        return pd.DataFrame()

# LB arkası gerçek istemci IP seçimi
def _pick_client_ip(row):
    for h in ["cs(X-Forwarded-For)", "cs(Client-IP)", "cs(X-Real-IP)"]:
        if h in row and pd.notna(row[h]) and str(row[h]).strip() not in ("", "-"):
            return str(row[h]).split(",")[0].strip()
    return row.get('client-ip', row.get('c-ip', ''))

# Logları ön işleme
def preprocess_logs(df, resolve_hostnames, resolve_geo_ip, selected_timezone):
    df.columns = df.columns.str.lower()
    if 'client-ip' not in df.columns and 'c-ip' in df.columns:
        df.rename(columns={'c-ip': 'client-ip'}, inplace=True)

    if "date" in df.columns and "time" in df.columns:
        df["datetime"] = pd.to_datetime(df["date"] + " " + df["time"], errors="coerce", utc=True)
        df = df.dropna(subset=['datetime'])
        try:
            df["datetime"] = df["datetime"].dt.tz_convert(selected_timezone)
        except Exception:
            st.warning("Zaman dilimi dönüşümünde sorun yaşandı, UTC olarak gösteriliyor.")
        df["hour"] = df["datetime"].dt.hour
        df["hour_label"] = df["hour"].apply(lambda h: f"{h:02d}:00-{(h+1)%24:02d}:00")
        df["date_only"] = df["datetime"].dt.date
        df["weekday"] = df["datetime"].dt.day_name()

    if "cs-uri-stem" in df.columns:
        df["extension"] = df["cs-uri-stem"].str.extract(r'(\.[a-zA-Z0-9]+)$')
        df["cs-uri-stem"] = df["cs-uri-stem"].apply(lambda x: x.split('?')[0])

    if "time-taken" in df.columns:
        df["time-taken"] = pd.to_numeric(df["time-taken"], errors="coerce")

    if "sc-status" in df.columns:
        df["sc-status"] = df["sc-status"].astype(str)

    if "client-ip" in df.columns or "c-ip" in df.columns or \
       "cs(x-forwarded-for)" in df.columns or "cs(client-ip)" in df.columns or "cs(x-real-ip)" in df.columns:
        df['client-ip'] = df.apply(_pick_client_ip, axis=1)

    if "client-ip" in df.columns:
        if resolve_hostnames:
            df["hostname"] = df["client-ip"].apply(get_hostname)
        if resolve_geo_ip:
            df[['latitude', 'longitude', 'country']] = df['client-ip'].apply(lambda ip: pd.Series(get_geo_location(ip)))

    if "cs(user-agent)" in df.columns:
        df['user_agent_parsed'] = df['cs(user-agent)'].apply(lambda ua: user_agents.parse(ua))
        df['os'] = df['user_agent_parsed'].apply(lambda ua: ua.os.family)
        df['browser'] = df['user_agent_parsed'].apply(lambda ua: ua.browser.family)
        df['os_version'] = df['user_agent_parsed'].apply(lambda ua: ua.os.version_string)

    return df

# Butona basıldığında veriyi yükle ve işle
if run_analysis_button:
    raw_logs = pd.DataFrame()
    if log_source == "Klasör":
        if folder and os.path.isdir(folder):
            with st.spinner("⏳ Klasördeki loglar yükleniyor..."):
                raw_logs = load_logs_from_folder_cached(folder)
        else:
            st.error("Lütfen geçerli bir klasör yolu girin.")
    elif log_source == "Tek dosya":
        if uploaded_file:
            with st.spinner("⏳ Dosya yükleniyor..."):
                raw_logs = load_log_file(uploaded_file)
        else:
            st.error("Lütfen bir log dosyası seçin.")
    if not raw_logs.empty:
        with st.spinner("⏳ Loglar işleniyor ve seçilen özellikler çözümleniyor..."):
            st.session_state.df = preprocess_logs(raw_logs, resolve_hostnames, resolve_geo_ip, selected_timezone)
    else:
        st.warning("Veri yüklenemedi. Lütfen geçerli bir kaynak seçtiğinizden emin olun.")

# Dashboard
if 'df' in st.session_state and not st.session_state.df.empty:
    df = st.session_state.df

    # Referer sütununu tekilleştir
    referer_col = None
    for cand in ['cs(referer)', 'cs(Referer)']:
        if cand in df.columns:
            referer_col = cand
            break

    # ---
    # 🔎 Filtreleme
    st.sidebar.header("🔎 Filtreleme")

    unique_dates = df["date_only"].unique()
    min_date = df["date_only"].min() if len(unique_dates) else None
    max_date = df["date_only"].max() if len(unique_dates) else None

    if min_date and max_date:
        date_range = st.sidebar.slider(
            "Tarih Aralığı Seç",
            min_value=min_date,
            max_value=max_date,
            value=(min_date, max_date),
            format="YYYY-MM-DD"
        )
        filtered_df = df[(df["date_only"] >= date_range[0]) & (df["date_only"] <= date_range[1])]
    else:
        filtered_df = df.copy()

    if 'sc-status' in filtered_df.columns:
        status_filter = st.sidebar.multiselect("Durum Kodu Seç", sorted(filtered_df["sc-status"].unique()), default=[])
        if status_filter:
            filtered_df = filtered_df[filtered_df["sc-status"].isin(status_filter)]

    if 'cs-method' in filtered_df.columns:
        method_filter = st.sidebar.multiselect("HTTP Metot Seç", sorted(filtered_df["cs-method"].unique()), default=[])
        if method_filter:
            filtered_df = filtered_df[filtered_df["cs-method"].isin(method_filter)]

    # 🤖 Bot filtreleme
    st.sidebar.header("🤖 Bot Filtreleme")
    hide_bots = st.sidebar.checkbox("Bilinen botları gizle", value=False)

    def _looks_like_bot(ua_str: str) -> bool:
        if not isinstance(ua_str, str): return False
        s = ua_str.lower()
        bot_signals = ["bot", "spider", "crawler", "pingdom", "uptime", "monitor", "curl", "wget", "python-requests"]
        return any(b in s for b in bot_signals)

    if hide_bots and 'cs(user-agent)' in filtered_df.columns:
        filtered_df = filtered_df[~filtered_df['cs(user-agent)'].apply(_looks_like_bot)]

    # 🧩 Alan görünürlüğü
    st.sidebar.header("🧩 Alan Görünürlüğü")
    all_cols = [c for c in filtered_df.columns if c not in ('user_agent_parsed',)]
    default_cols = [c for c in ['datetime', 'client-ip', 'cs-method', 'cs-uri-stem', 'sc-status', 'time-taken'] if c in all_cols]
    show_cols = st.sidebar.multiselect("Tablolarda gösterilecek alanlar", all_cols, default=default_cols)

    # 💾 Dışa aktar
    st.sidebar.header("💾 Dışa Aktar")
    st.sidebar.download_button(
        "CSV indir (filtreli)",
        data=filtered_df.to_csv(index=False).encode('utf-8'),
        file_name="iis_filtered.csv",
        mime="text/csv"
    )
    try:
        import pyarrow as pa, pyarrow.parquet as pq
        table = pa.Table.from_pandas(filtered_df)
        buf = io.BytesIO()
        pq.write_table(table, buf)
        buf.seek(0)
        st.sidebar.download_button("Parquet indir (filtreli)", data=buf, file_name="iis_filtered.parquet", mime="application/octet-stream")
    except Exception:
        pass

    # ---
    ## 🧾 Genel Trafik Özeti
    st.subheader("🧾 Genel Trafik Özeti")

    col1, col2, col3 = st.columns(3)
    col1.metric("Toplam İstek Sayısı", len(filtered_df))
    col2.metric("Gün Sayısı", filtered_df["date_only"].nunique() if 'date_only' in filtered_df.columns else "N/A")
    col3.metric("Benzersiz IP", filtered_df["client-ip"].nunique() if 'client-ip' in filtered_df.columns else "N/A")

    col4, col5, col6 = st.columns(3)
    col4.metric("İlk Kayıt", str(filtered_df["datetime"].min().date()) if 'datetime' in filtered_df.columns and not filtered_df.empty else "N/A")
    col5.metric("Son Kayıt", str(filtered_df["datetime"].max().date()) if 'datetime' in filtered_df.columns and not filtered_df.empty else "N/A")
    col6.metric("Ort. Yanıt Süresi (ms)", f"{filtered_df['time-taken'].mean():.2f}" if 'time-taken' in filtered_df.columns and filtered_df['time-taken'].notna().any() else "N/A")

    # 95p & 99p + hata oranı
    p95 = p99 = None
    if 'time-taken' in filtered_df.columns and filtered_df['time-taken'].notna().any():
        p95 = filtered_df['time-taken'].quantile(0.95)
        p99 = filtered_df['time-taken'].quantile(0.99)
    error_rate = None
    if 'sc-status' in filtered_df.columns and len(filtered_df) > 0:
        error_rate = (filtered_df['sc-status'].str.startswith(('4', '5'), na=False).mean()) * 100
    col7, col8 = st.columns(2)
    col7.metric("P95 Yanıt (ms)", f"{p95:.0f}" if p95 is not None else "N/A")
    col8.metric("P99 Yanıt (ms)", f"{p99:.0f}" if p99 is not None else "N/A")
    if error_rate is not None:
        st.markdown(f"**Hata Oranı:** {error_rate:.2f}%")

    st.metric("En Çok İstenen Sayfa", filtered_df['cs-uri-stem'].mode()[0] if 'cs-uri-stem' in filtered_df.columns and not filtered_df['cs-uri-stem'].empty else "N/A")

    # ---
    ## 🕒 Saatlik Trafik
    if "hour_label" in filtered_df.columns and not filtered_df.empty:
        st.subheader("🕒 Saatlik Trafik")
        hour_count = filtered_df["hour_label"].value_counts().sort_index()
        fig = px.bar(x=hour_count.index, y=hour_count.values,
                     labels={'x': 'Saat Aralığı', 'y': 'İstek Sayısı'},
                     text=hour_count.values,
                     color=hour_count.index,
                     color_discrete_sequence=colors)
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

    # ---
    ## 📅 Günlük Trafik
    if {'date_only', 'weekday'}.issubset(filtered_df.columns):
        st.subheader("📅 Günlük Trafik")
        daily = filtered_df.groupby(["date_only", "weekday"]).size().reset_index(name="count")
        daily["label"] = daily["date_only"].astype(str) + " (" + daily["weekday"] + ")"
        fig = px.bar(daily, x="label", y="count",
                     labels={'label': 'Tarih (Gün)', 'count': 'İstek'},
                     color="weekday",
                     color_discrete_sequence=colors)
        st.plotly_chart(fig, use_container_width=True)

    # ---
    ## 🗓️ Saat x Gün Isı Haritası
    if {'weekday', 'hour', 'cs-uri-stem'}.issubset(filtered_df.columns):
        st.subheader("🗓️ Saat x Gün Isı Haritası")
        heat = (filtered_df
                .groupby(['weekday', 'hour'])['cs-uri-stem'].count()
                .rename('count')
                .reset_index())
        weekday_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        heat['weekday'] = pd.Categorical(heat['weekday'], categories=weekday_order, ordered=True)
        heat_pivot = heat.pivot(index='weekday', columns='hour', values='count').fillna(0)
        cont_scale = 'Turbo' if selected_palette not in ['Turbo'] else selected_palette
        fig_heat = px.imshow(heat_pivot, aspect="auto",
                             labels=dict(x="Saat", y="Gün", color="İstek"),
                             color_continuous_scale=cont_scale)
        st.plotly_chart(fig_heat, use_container_width=True)

    # ---
    ## 🧭 HTTP Durum Kodları
    if "sc-status" in filtered_df.columns:
        st.subheader("🧭 HTTP Durum Kodları")
        status_count = filtered_df["sc-status"].value_counts().sort_index()
        fig = px.bar(x=status_count.index.astype(str), y=status_count.values,
                     labels={'x': 'Durum Kodu', 'y': 'İstek Sayısı'},
                     text=status_count.values,
                     color=status_count.index.astype(str),
                     color_discrete_sequence=colors)
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

        # 🎯 HTTP sınıf dağılımı
        st.subheader("🎯 HTTP Sınıf Dağılımı")
        cls = filtered_df['sc-status'].str[0].map({'1': '1xx', '2': '2xx', '3': '3xx', '4': '4xx', '5': '5xx'})
        cls_count = cls.value_counts().reindex(['1xx', '2xx', '3xx', '4xx', '5xx']).fillna(0)
        fig_cls = px.bar(x=cls_count.index, y=cls_count.values,
                         labels={'x': 'Sınıf', 'y': 'İstek'},
                         color=cls_count.index, color_discrete_sequence=colors)
        st.plotly_chart(fig_cls, use_container_width=True)

    # IIS hata ipuçları
    IIS_HINTS = {
        "401": "Kimlik doğrulama başarısız. Yetkilendirme ve Anonymous/Windows Auth konfigürasyonunu kontrol edin.",
        "403": "Erişim yasak. IP Restrictions, Directory Browsing, Authorization Rules ayarlarını gözden geçirin.",
        "404": "Kaynak yok. Route/Static file/Rewrite ayarlarını kontrol edin.",
        "500": "Sunucu hatası. Uygulama loglarını ve exception middleware'i inceleyin."
    }
    if 'sc-status' in filtered_df.columns:
        top_err = (filtered_df[filtered_df['sc-status'].str.startswith(('4', '5'), na=False)]['sc-status']
                   .value_counts().index.tolist()[:1])
        if top_err:
            major = top_err[0][:3]
            if major in IIS_HINTS:
                st.info(f"💡 En sık hata {top_err[0]}: {IIS_HINTS[major]}")

    # ---
    ## 📊 Trafik Metot Dağılımı
    if 'cs-method' in filtered_df.columns:
        st.subheader("📊 Trafik Metot Dağılımı")
        method_counts = filtered_df['cs-method'].value_counts()
        fig_methods = px.pie(values=method_counts.values, names=method_counts.index,
                             title="HTTP Metot Dağılımı",
                             color_discrete_sequence=colors)
        st.plotly_chart(fig_methods, use_container_width=True)

    # ---
    ## ⚠️ Hata Analizi (4xx ve 5xx)
    if "sc-status" in filtered_df.columns:
        st.subheader("⚠️ Hata Analizi (4xx ve 5xx)")
        error_df = filtered_df[filtered_df["sc-status"].str.startswith(('4', '5'), na=False)]

        if not error_df.empty:
            st.markdown("##### En Çok Karşılaşılan Hatalar")
            status_error_count = error_df["sc-status"].value_counts()
            fig_errors = px.bar(
                x=status_error_count.index.astype(str),
                y=status_error_count.values,
                labels={'x': 'Hata Kodu', 'y': 'Sayı'},
                color=status_error_count.index.astype(str),
                color_discrete_sequence=colors
            )
            st.plotly_chart(fig_errors, use_container_width=True)

            if 'cs-uri-stem' in error_df.columns:
                st.markdown("##### Hata Veren En Çok İstenen Sayfalar")
                uri_error_count = error_df["cs-uri-stem"].value_counts().nlargest(10)
                fig_uri_errors = px.bar(
                    x=uri_error_count.values,
                    y=uri_error_count.index,
                    orientation='h',
                    labels={'x': 'Sayı', 'y': 'URI'},
                    color=uri_error_count.index,
                    color_discrete_sequence=colors
                )
                st.plotly_chart(fig_uri_errors, use_container_width=True)

        else:
            st.info("Seçilen aralıkta herhangi bir hata kodu (4xx veya 5xx) bulunamadı.")

    # ---
    ## 🔗 404 Analizi: URI x Referer
    if 'sc-status' in filtered_df.columns and 'cs-uri-stem' in filtered_df.columns:
        st.subheader("🔗 404 Analizi: URI x Referer")
        notfound = filtered_df[filtered_df['sc-status'].str.startswith('404', na=False)]
        if not notfound.empty and referer_col:
            top404 = (notfound.groupby(['cs-uri-stem', referer_col])
                      .size().reset_index(name='count')
                      .sort_values('count', ascending=False).head(20))
            fig404 = px.bar(top404, x='count', y='cs-uri-stem', color=referer_col,
                            orientation='h', color_discrete_sequence=colors)
            st.plotly_chart(fig404, use_container_width=True)

    # ---
    ## 📂 Dosya Uzantıları
    if "extension" in filtered_df.columns:
        st.subheader("📂 Dosya Uzantıları")
        ext_count = filtered_df["extension"].value_counts().nlargest(10)
        fig = px.bar(x=ext_count.values, y=ext_count.index, orientation='h',
                     labels={'x': 'İstek', 'y': 'Uzantı'},
                     text=ext_count.values,
                     color=ext_count.index,
                     color_discrete_sequence=colors)
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, use_container_width=True)

    # ---
    ## 🌐 Tarayıcı ve İşletim Sistemi Dağılımı
    if "os" in filtered_df.columns:
        st.subheader("🌐 Tarayıcı ve İşletim Sistemi Dağılımı")

        col_ua1, col_ua2 = st.columns(2)

        with col_ua1:
            os_counts = filtered_df['os'].value_counts().nlargest(5)
            fig_os = px.pie(values=os_counts.values, names=os_counts.index,
                            title='İşletim Sistemi Dağılımı',
                            color_discrete_sequence=colors)
            st.plotly_chart(fig_os, use_container_width=True)

        with col_ua2:
            browser_counts = filtered_df['browser'].value_counts().nlargest(5)
            fig_browser = px.pie(values=browser_counts.values, names=browser_counts.index,
                                 title='Tarayıcı Dağılımı',
                                 color_discrete_sequence=colors)
            st.plotly_chart(fig_browser, use_container_width=True)

    # ---
    ## 🌐 HTTP Versiyon ve Referans Kaynağı Analizi
    st.subheader("🌐 HTTP Versiyon ve Referans Kaynağı Analizi")
    col_ref1, col_ref2 = st.columns(2)

    if 'cs-protocol-version' in filtered_df.columns:
        with col_ref1:
            http_version_counts = filtered_df['cs-protocol-version'].value_counts()
            fig_http_version = px.pie(values=http_version_counts.values, names=http_version_counts.index,
                                      title='HTTP Versiyon Dağılımı',
                                      color_discrete_sequence=colors)
            st.plotly_chart(fig_http_version, use_container_width=True)

    if referer_col:
        with col_ref2:
            referrer_counts = filtered_df[referer_col].value_counts().nlargest(10)
            fig_referrer = px.bar(x=referrer_counts.values, y=referrer_counts.index, orientation='h',
                                  title='En Çok Referans Veren Kaynaklar',
                                  labels={'x': 'İstek Sayısı', 'y': 'Referans Kaynağı'},
                                  color=referrer_counts.index,
                                  color_discrete_sequence=colors)
            st.plotly_chart(fig_referrer, use_container_width=True)

    # ---
    ## 🐢 Performans Analizi
    if "time-taken" in filtered_df.columns:
        st.subheader("🐢 Performans Analizi")

        st.markdown("##### Yanıt Süresi Dağılımı")
        fig_hist = px.histogram(filtered_df, x="time-taken", nbins=50,
                                title='Yanıt Süresi Dağılımı (ms)',
                                labels={'time-taken': 'Yanıt Süresi (ms)'},
                                color_discrete_sequence=colors)
        st.plotly_chart(fig_hist, use_container_width=True)

        # Gecikme vs Yanıt Boyutu korelasyonu (varsa)
        if {'time-taken', 'sc-bytes'}.issubset(filtered_df.columns):
            st.subheader("📦 Gecikme vs Yanıt Boyutu")
            sample = filtered_df[['time-taken', 'sc-bytes']].dropna()
            if len(sample) > 20000:
                sample = sample.sample(20000, random_state=42)
            try:
                fig_sc = px.scatter(sample, x='sc-bytes', y='time-taken',
                                    labels={'sc-bytes': 'Yanıt Boyutu (byte)', 'time-taken': 'Süre (ms)'},
                                    trendline="ols", color_discrete_sequence=colors)
            except Exception:
                fig_sc = px.scatter(sample, x='sc-bytes', y='time-taken',
                                    labels={'sc-bytes': 'Yanıt Boyutu (byte)', 'time-taken': 'Süre (ms)'},
                                    color_discrete_sequence=colors)
            st.plotly_chart(fig_sc, use_container_width=True)

        st.markdown("##### En Yavaş ve En Hızlı Sayfalar")
        col_perf1, col_perf2 = st.columns(2)

        if 'cs-uri-stem' in filtered_df.columns:
            with col_perf1:
                slowest_pages = filtered_df.groupby('cs-uri-stem')['time-taken'].mean().nlargest(10).reset_index()
                slowest_pages = slowest_pages.rename(columns={'cs-uri-stem': 'Sayfa', 'time-taken': 'Ort. Yanıt (ms)'})
                st.markdown("###### En Yavaş 10 Sayfa (Ortalama Yanıt Süresi)")
                st.dataframe(safe_view(slowest_pages, ['Sayfa', 'Ort. Yanıt (ms)']))

            with col_perf2:
                fastest_pages = filtered_df.groupby('cs-uri-stem')['time-taken'].mean().nsmallest(10).reset_index()
                fastest_pages = fastest_pages.rename(columns={'cs-uri-stem': 'Sayfa', 'time-taken': 'Ort. Yanıt (ms)'})
                st.markdown("###### En Hızlı 10 Sayfa (Ortalama Yanıt Süresi)")
                st.dataframe(safe_view(fastest_pages, ['Sayfa', 'Ort. Yanıt (ms)']))

        # 💸 En pahalı çağrılar (sıklık x ort. süre)
        if 'cs-uri-stem' in filtered_df.columns:
            st.subheader("💸 En Pahalı Çağrılar (Sıklık x Ortalama Süre)")
            agg = (filtered_df
                   .groupby('cs-uri-stem')
                   .agg(İstek=('cs-uri-stem', 'count'),
                        **({'Ort. ms': ('time-taken', 'mean')} if 'time-taken' in filtered_df.columns else {})))
            if 'Ort. ms' in agg.columns:
                agg['Skor'] = agg['İstek'] * agg['Ort. ms']
                pricey = agg.sort_values('Skor', ascending=False).head(10).reset_index().rename(columns={'cs-uri-stem': 'Sayfa'})
                st.dataframe(safe_view(pricey, ['Sayfa', 'İstek', 'Ort. ms', 'Skor']))

    # ---
    ## 🌍 Şüpheli IP ve Coğrafi Konum Analizi
    if "client-ip" in filtered_df.columns:
        st.subheader("🌍 Şüpheli IP ve Coğrafi Konum Analizi")

        col_sec1, col_sec2 = st.columns(2)

        with col_sec1:
            ip_counts = filtered_df.groupby('client-ip').size()
            if not ip_counts.empty:
                max_requests_per_ip = ip_counts.max()
                suspicious_threshold = max(max_requests_per_ip * 0.1, 100)
                suspicious_ips = ip_counts[ip_counts > suspicious_threshold].reset_index(name='İstek Sayısı')
                if not suspicious_ips.empty:
                    st.markdown("##### Şüpheli IP Adresleri (Aşırı İstek)")
                    st.dataframe(safe_view(suspicious_ips, ['client-ip', 'İstek Sayısı']))
                else:
                    st.info("Aşırı istek yapan şüpheli IP bulunamadı.")

        with col_sec2:
            if 'sc-status' in filtered_df.columns:
                error_ips = filtered_df[filtered_df['sc-status'].str.startswith(('4', '5'), na=False)]['client-ip'] \
                    .value_counts().nlargest(10).reset_index()
                if not error_ips.empty:
                    st.markdown("##### En Çok Hata Üreten IP'ler")
                    error_ips = error_ips.rename(columns={'index': 'IP', 'client-ip': 'Hata Sayısı'})
                    st.dataframe(safe_view(error_ips, ['IP', 'Hata Sayısı']))

    # Harita (MarkerCluster)
    if resolve_geo_ip and 'latitude' in filtered_df.columns:
        st.markdown("### 🌍 Dünya Haritası Üzerinde Trafik (Cluster)")
        map_df = filtered_df.dropna(subset=['latitude', 'longitude'])
        if not map_df.empty:
            from folium.plugins import MarkerCluster
            m = folium.Map(location=[map_df['latitude'].mean(), map_df['longitude'].mean()], zoom_start=2)
            mc = MarkerCluster().add_to(m)
            for _, row in map_df.iterrows():
                folium.Marker(
                    location=[row['latitude'], row['longitude']],
                    tooltip=f"IP: {row.get('client-ip','')} • {row.get('country','')}"
                ).add_to(mc)
            folium_static(m)

    # ---
    ## 🐢 En Yavaş 10 İstek + Karşılaştırma
    st.subheader("🐢 En Yavaş 10 İstek")
    slowest = filtered_df.sort_values("time-taken", ascending=False).head(10).reset_index()
    if not slowest.empty:
        cols_for_slowest = [c for c in ['datetime', 'cs-method', 'cs-uri-stem', 'time-taken', 'client-ip'] if c in slowest.columns]
        st.dataframe(safe_view(slowest, cols_for_slowest))

        def _guess_request_id(row):
            id_candidates = [
                'x-request-id', 'request-id', 'traceidentifier', 'activityid', 'requestid',
                'correlation-id', 'correlationid', 'x-correlation-id'
            ]
            for c in id_candidates:
                if c in slowest.columns and pd.notna(row.get(c, None)) and str(row.get(c)).strip() not in ('', '-'):
                    return str(row.get(c))
            return f"{row.get('datetime','')}|{row.get('client-ip','')}"

        def _format_option(i: int):
            r = slowest.loc[i]
            rid = _guess_request_id(r)
            uri = str(r.get('cs-uri-stem', ''))
            tt = r.get('time-taken', '')
            try:
                tt_val = float(tt)
                tt = f"{int(tt_val)} ms"
            except Exception:
                tt = str(tt)
            return f"{i} | {rid} | {uri} | {tt}"

        selected = st.multiselect("Karşılaştırılacak 2 isteği seçin:", options=slowest.index.tolist(),
                                  format_func=_format_option, max_selections=2)

        if len(selected) == 2:
            st.markdown("### 🔍 İstek Karşılaştırması")
            left = slowest.loc[selected[0]].dropna()
            right = slowest.loc[selected[1]].dropna()
            keys = list(dict.fromkeys(list(left.index) + list(right.index)))
            priority = ["datetime", "client-ip", "cs-method", "cs-uri-stem", "cs-uri-query",
                        "sc-status", "time-taken", "cs(referer)", "cs(user-agent)"]
            keys = priority + [k for k in keys if k not in priority]
            rows = []
            for k in keys:
                v1 = str(left.get(k, ''))
                v2 = str(right.get(k, ''))
                rows.append({"Alan": k, "İstek 1": v1, "İstek 2": v2, "Farklı": v1 != v2})
            comp = pd.DataFrame(rows)
            comp['≠'] = comp['Farklı'].map({True: '❗', False: ''})
            st.table(comp[['Alan', 'İstek 1', 'İstek 2', '≠']])
            st.caption("Seçilen isteklerin RequestId/CorrelationId değerlerini kopyalayıp uygulama loglarında arayın.")
    else:
        st.info("Seçilen tarih aralığında yavaş istek bulunamadı.")

    # ---
    ## 🌍 En Aktif IP Adresleri
    if "client-ip" in filtered_df.columns:
        st.subheader("🌍 En Aktif IP Adresleri")
        if resolve_hostnames and 'hostname' in filtered_df.columns:
            ip_count = filtered_df.groupby(["client-ip", "hostname"]).size().reset_index(name="İstek")
            top10 = ip_count.sort_values(by="İstek", ascending=False).head(10)
            st.dataframe(safe_view(top10, ['client-ip', 'hostname', 'İstek']))
        else:
            ip_count = filtered_df["client-ip"].value_counts().reset_index()
            ip_count.columns = ["IP", "İstek"]
            top10 = ip_count.head(10)
            st.dataframe(safe_view(top10, ['IP', 'İstek']))

        if st.checkbox("Tüm IP'leri göster"):
            st.dataframe(ip_count.sort_values(by="İstek", ascending=False))
