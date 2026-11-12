# wsb-triage — genel inceleme

İnceleme tarihi: 11 Kasım 2026, commit `cb78e43`.

Bu belge kodun tamamı okunarak hazırlandı. "Doğrulandı" yazan maddeler kodda ya da küçük bir denemeyle teyit edildi. Hiçbir madde henüz düzeltilmedi.

## Önce bilinmesi gereken

**Gerçek Windows Sandbox içinde hiçbir şey çalıştırılmadı.** Bu bilgisayarda Sandbox hâlâ kapalı. Şimdiye kadarki bütün testlerde izleme scripti ana bilgisayarda test modunda çalıştırıldı. Aşağıdaki parçalar bu yüzden hiç denenmedi:

- `pktmon` ile ağ kaydı ve `.pcapng` dönüşümü
- Yerel ağ engelleme kuralı (sandbox'ın kendi ağ geçidi ve DNS'i gerçekten açık kalıyor mu)
- İşlem başlatma izleme (`Win32_ProcessStartTrace`), yönetici yetkisi varsayımı
- Sandbox'ı kapatma: Windows 11 24H2 ve sonrasında Sandbox ayrı bir uygulama olarak geliyor, işlem adları ve `wsb` komutu farklı olabilir
- 1 GB üstü kurulumun salt okunur klasörden yerinde çalışması
- VirusTotal çağrıları (API anahtarı hiç girilmedi, sahte istemciyle test edildi)

İlk iş Sandbox'ı açıp demo paketiyle uçtan uca bir deneme yapmak olmalı. Aşağıdaki listeden önce bu gelir.

## A. Hatalar ve güvenlik açıkları

Önem sırasına göre.

### A1. Otomatik analiz kişisel dosyaları VirusTotal'e yükleyebilir (yüksek) — ✅ DÜZELTİLDİ

> **Düzeltme (11 Kasım 2026):** İzleyicinin başlattığı analizler artık hiçbir dosya yüklemiyor, sadece hash soruyor. Elle başlatılan analizlerde de yalnızca programlar ve scriptler yükleniyor; arşivin kendisi ancak içinde program varsa yükleniyor (`pipeline.py`, `_uploadable`). Test edildi: `license.pdf`, `foto.jpg` ve belge dolu bir zip yüklenmedi, `setup.exe` yüklendi.

- **Nerede:** `pipeline.py:495` ve `pipeline.py:1030`
- **Sorun:** VirusTotal adımı, analiz edilen dosyanın kendisini her zaman listeye ekliyor. İndirilenler izleyicisi de otomatik analizde "bilinmeyenleri yükle" seçeneği açık olarak iş başlatıyor. Sonuç: izleyici açıkken indirdiğin bir banka dökümü, sözleşme ya da fotoğraf arşivi, 650 MB'ın altındaysa VirusTotal'e yüklenir. VirusTotal'in ücretli kullanıcıları yüklenen dosyaları indirebilir.
- **Düzeltme:** İzleyicinin başlattığı işlerde yükleme kapalı olsun, sadece hash sorgusu yapılsın. Ayrıca dosyanın kendisi yalnızca çalıştırılabilir dosya ya da arşivse yüklensin.

### A2. Sandbox'tan gelen veri panelde kod çalıştırabilir (yüksek) — ✅ DÜZELTİLDİ

> **Düzeltme (11 Kasım 2026):** İki katman. Panel: kutu başlıkları da güvenli gösteriliyor, sandbox'tan gelen diziler ve sayılar tür kontrolünden geçiyor (`asArr` / `asNum`). Sunucu: `live.json` ve `behavior.json` okunur okunmaz beklenen biçime getiriliyor (`pipeline.py`, `sanitize_sandbox_json`); yanlış türler artık değerlendirme kodunu da çökertemiyor. Test edildi: temizleyici atlanarak 15 alana yerleştirilen zararlı kodun hiçbiri panelde çalışmadı.

- **Nerede:** `static/index.html:487` ve `listBox` fonksiyonu (`index.html:453`)
- **Sorun:** Paneldeki hemen her değer güvenli gösteriliyor, biri hariç. `behavior.json` içindeki `Files.NewCount` değeri başlığa olduğu gibi yazılıyor. Bu dosyayı sandbox içindeki program yazabilir. Sayı yerine HTML koyarsa panelde JavaScript çalışır (XSS). Panel kendi API'sine tam erişimli olduğu için bu kod izleyiciyi Belgeler klasörüne çevirebilir, VirusTotal anahtarını değiştirebilir, yeni analiz başlatabilir.
- **Düzeltme:** `listBox` başlığı da `esc()` ile gösterilsin, `NewCount` sayıya çevrilsin. Ek katman olarak sunucu, sandbox'tan gelen JSON'u okurken alanların türünü doğrulasın (sayı beklenen yerde sayı).

### A3. Çok parçalı arşivlerde ilk parça atlanıyor (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** `is_later_volume()` parça numarasını sayıya çeviriyor; `.part01.rar`, `.part001.rar`, `.001` ilk parça, `setup.2024` gibi adlar parça değil. Panelden elle bir ara parça seçilirse açık bir hata mesajı veriliyor. Test: 15 ad doğru sınıflandı.

- **Nerede:** `pipeline.py`, izleyicideki `later_part` deseni
- **Sorun:** `.part01.rar` ve `.part001.rar` "sonraki parça" sayılıyor, yani otomatik analiz hiç başlamıyor. 10 ve üzeri parçalı arşivlerde ilk parçanın adı tam olarak böyle olur. Aynı desen `setup.2024` ya da `app-1.2.10` gibi sayıyla biten adları da yanlışlıkla parça sayıyor.
- **Düzeltme:** Parça numarasını sayıya çevirip 1'den büyük mü diye bakmak. Sayısal uzantı kuralı yalnızca `.002`, `.003` gibi üç haneli uzantılara uygulanmalı.

### A4. Klasöre taşınan dosyalar izleyicide görünmüyor (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** İzleme açılınca klasörün listesi (boyut + değiştirilme zamanı) alınıyor; sonradan beliren ya da değişen her dosya yeni sayılıyor. Test: 2000 tarihli taşınmış dosya ve üzerine yazılmış eski dosya listelendi.

- **Nerede:** `pipeline.py:1016`
- **Sorun:** İzleyici "yeni dosya"yı değiştirilme tarihine göre belirliyor. Başka klasörden taşınan ya da sunucudaki tarihini koruyan bir indirme eski tarihli görünür ve hiç listelenmez.
- **Düzeltme:** İzleme açıldığı anda klasördeki dosyaların listesini almak, sonradan beliren her dosyayı yeni saymak.

### A5. Sandbox aynı analiz için iki kez başlatılabilir (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** Kontrol ve işaretleme tek adımda, kilit altında; çalışan ya da sıradaki analize ikinci istek 409 alıyor. Test: art arda 3 istekten 1'i başladı, 2'si reddedildi.

- **Nerede:** `app.py:204-209`
- **Sorun:** Kontrol sadece "çalışıyor" durumuna bakıyor. Analiz "sırada" beklerken ya da butona hızlıca iki kez basılınca ikinci bir iş parçacığı başlıyor. İkisi sırayla aynı klasörde sandbox çalıştırıyor, ilkinin çıktısı yedek klasöre itiliyor.
- **Düzeltme:** İş başına bir "sandbox istendi" kilidi. "Sırada" durumu da reddedilsin.

### A6. Bulut alan adları "gürültü" sayılıyor (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** Gürültü listesinde artık sadece Microsoft'un kendi alan adları var. Azure/Akamai/AWS/Google Cloud vb. "Paylaşımlı bulut — incele" (not). Ek olarak yeni bir "Kötüye kullanıma açık servis" sınıfı: Telegram/Discord API, paste siteleri, ngrok/Cloudflare tünelleri, dinamik DNS, anonim dosya paylaşımı ve IP sorgulama servisleri — bunlar **kırmızı** bayrak.

- **Nerede:** `pipeline.py:723-725`
- **Sorun:** `windows.net`, `azureedge.net`, `azurefd.net`, `trafficmanager.net`, `akamaized.net` Microsoft gürültüsü olarak sınıflanıyor. Bunlar herkesin kiralayabildiği altyapılar. Zararlılar verileri sık sık `*.blob.core.windows.net` gibi adreslere gönderir. Böyle bir bağlantı raporda gri görünür ve kırmızı listeye girmez.
- **Düzeltme:** Bu alan adlarını listeden çıkarıp ayrı bir "paylaşımlı bulut — incele" sınıfına almak.

### A7. Uzun süren yardımcı komutlar bütün analizi düşürüyor (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** İmza kontrolü 500'lük gruplarla; süreyi aşan grubun dosyaları "Unknown" sayılıp günlüğe yazılıyor. Her tshark sorgusu ayrı; zaman aşımında ağ özeti "kısmi" diye işaretleniyor ve not düşülüyor. Test: iki zaman aşımı da analizi düşürmedi.

- **Nerede:** `pipeline.py:372` (imza kontrolü), `pipeline.py:746` (tshark)
- **Sorun:** Zaman aşımı olursa hata yakalanmıyor. Binlerce dosyalı bir kurulumda imza kontrolü, büyük bir ağ kaydında tshark süreyi aşarsa analiz "hata" ile bitiyor ve o ana kadarki sonuçlar rapora girmiyor.
- **Düzeltme:** Zaman aşımını yakalayıp adımı "kısmen tamamlandı" olarak işaretlemek. İmza kontrolünü 500'lük gruplara bölmek.

### A8. Arşiv açmada boyut sınırı yok (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** Açmadan önce içerik listeleniyor (`7z l -slt` ya da zip başlıkları). Toplam boyut boş alanı (2 GB payla) aşarsa ya da sıkıştırma oranı 1000 katı geçerse (ve 1 GB'tan büyükse) arşiv açılmıyor. Çok parçalı arşivlerde oran tüm parçaların toplamına göre hesaplanıyor. Test: 1,1 MB'lık, 1,1 GB'a açılan bir zip reddedildi, hiçbir şey yazılmadı.

- **Nerede:** `pipeline.py`, `stage_extract`
- **Sorun:** Küçük görünen bir arşiv açılınca yüzlerce GB olabilir (zip bombası) ve diski doldurur.
- **Düzeltme:** Açmadan önce `7z l` ile toplam boyutu okuyup boş alanla karşılaştırmak.

### A9. Statik puan neredeyse her dosyada yüksek çıkıyor (orta) — ✅ DÜZELTİLDİ

> **Düzeltme:** Tek tek API'ler artık puan getirmiyor; zararlılara özgü birleşimler puanlanıyor (süreç enjeksiyonu, process hollowing, indir-çalıştır, tuş kaydı, parola kasası, hata ayıklayıcıdan gizlenme). Metin izleri tek eşleşmede hafif, aynı kategoride birden fazla farklı izde ağır; her ek iz puanı artırıyor. `CryptUnprotectData` metin deseninden çıkarıldı (sistem DLL'lerinde zaten yazıyor). Entropi sadece kod bölümlerinde sayılıyor. Scriptler "imzasız" diye puan almıyor.
>
> **Ölçüm** (23 temiz Microsoft dosyası): ortalama 31 → 7, "orta" (≥35) 11 → 2, "yüksek" (≥65) 2 → 0. `winhttp.dll` 75 → 10. Sentetik örnekler: bilgi çalan benzeri 100, gizli PowerShell + Defender istisnalı yükleyici 70, sıradan kurulum scripti 6. Kalan iki "orta": `kernel32.dll` (bu API'leri sağlayan çekirdek DLL) ve `msedge.exe` (tarayıcılar alt işlemlerine gerçekten kod enjekte eder).

- **Nerede:** `analyzer.py:25-47` ve metin desenleri
- **Sorun:** `IsDebuggerPresent`, `QueryPerformanceCounter`, `ShellExecute`, `RegSetValueEx` hemen her Windows programında bulunur. `notepad.exe` bile 20 puan alıyor. `Login Data`, `Local State` gibi metinler Chromium gömülü her programda var ve "kritik" sayılıyor. `.bat` dosyaları imzalanamadığı halde "imzasız" diye puan alıyor. Puan ayırt edici değil.
- **Düzeltme:** Tek başına anlamsız API'leri listeden çıkarmak. Puanı tek API'ye değil birleşimlere vermek (örneğin `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` birlikte). Script dosyalarında imza durumunu saymamak.

### A10. VirusTotal günlük kotası dolunca adım dakikalarca bekliyor (düşük) — ✅ DÜZELTİLDİ

> **Düzeltme:** 429'da bir kez 60 sn bekleniyor (dakikalık pencere); ikinci 429 "kota doldu" sayılıp bütün VT adımı duruyor, kalan dosyalar "kota doldu" olarak işaretleniyor. Test: 4 dosyalık analiz 2 istekte durdu (önce 16 istek ve ~16 dk sürerdi).

- **Nerede:** `vt_client.py:83-85`
- **Sorun:** Her 429 yanıtında 60 saniye bekleyip 4 kez deniyor. Günlük kota (ücretsiz hesapta 500 istek) dolduysa her dosya için 4 dakika boşa gider.
- **Düzeltme:** Yanıttaki hata kodunu okuyup günlük kota dolmuşsa adımı hemen "kota doldu" diye bitirmek.

### A11. Büyük dosya yüklemesi belleği dolduruyor (düşük) — ✅ DÜZELTİLDİ

> **Düzeltme:** Yükleme gövdesi diskten parça parça okunarak gönderiliyor (`vt_client.StreamingMultipart`, ek paket gerekmedi). Ölçüm: 300 MB'lık yüklemede Python bellek tepe noktası 637 MB → 2 MB. Gövde geçerli multipart olarak çözülüyor.

- **Nerede:** `vt_client.py`, `upload`
- **Sorun:** `requests` çok parçalı gövdeyi bellekte oluşturur. 600 MB'lık bir yükleme 600 MB'tan fazla RAM kullanır.
- **Düzeltme:** `requests-toolbelt` ile akış halinde yükleme ya da yükleme sınırını 200 MB'a indirmek.

### A12. Küçük sorunlar — ✅ biri hariç DÜZELTİLDİ

- ✅ **Arşiv şifresi saklanıyor.** Şifre artık sadece bellekte tutuluyor; `state.json`'a ve API yanıtlarına hiç girmiyor (`has_password` bayrağı kalıyor).
- ✅ **"Bayrak yok" yanıltabilir.** VirusTotal ya da sandbox çalışmadıysa bu not olarak yazılıyor; yeşil sonuç sadece bütün kontroller çalıştığında çıkıyor (`verdict.not_run`).
- ✅ **Durum okuma yarışı.** Durum, eşzamanlı yazmaya dayanıklı tek bir `snapshot()` ile okunuyor ve kaydediliyor. Test: sürekli değişen durumda 2000 okuma, 0 hata.
- ✅ **Analizler hiç silinmiyor.** Panelde "🗑 Sil" (analiz klasörü + panele yüklenen kopya; kullanıcının kendi dosyasına dokunulmaz) ve "30 günden eskileri sil".
- ✅ **İş iptal edilemiyor.** "✖ İptal et": güvenli noktalarda (adım arası, dosya döngüleri, VT sorguları, sandbox sırası) duruyor. Sandbox çalışırken iptal, izlemeyi erken bitirip o ana kadarki sonuçları raporluyor. Test: VT adımının ortasında 0,9 sn'de durdu.
- ✅ **`Baslat.bat`.** Panel zaten açıksa sadece tarayıcıyı açıyor; Python ya da paketler eksikse ne yapılacağını söylüyor; tarayıcıyı sunucu yanıt verince açıyor; hata olursa pencereyi açık tutuyor.
- ⏳ **Defender sinyalleri sandbox'ta işe yaramayabilir.** Windows Sandbox içinde Defender genelde çalışmaz. "Defender tespitleri" ve "Defender değişiklikleri" kutuları boş kalabilir. Gerçek denemede bakılmalı.

## B. Geliştirilebilecek yerler

- **Panel dış kaynağa bağımlı.** — ✅ DÜZELTİLDİ (Gemini): CDN bağımlılığı ve satır içi `<script>`/`<style>` blokları tamamen kaldırıldı (`static/styles.css`, `static/app.js`, `static/auth.js`). `app.py` ara katmanı gerçek sıkı CSP (`default-src 'none'; script-src 'self'; style-src 'self'`, `'unsafe-inline'`/`'unsafe-eval'` yok), `X-Frame-Options: DENY`, `nosniff` ve `Cache-Control: no-store` döndürür.
- **Depoda test yok.** — ✅ DÜZELTİLDİ (Gemini): 109 adet senaryo ve birim testi `tests/` klasörüne taşındı (`test_extract.py`, `test_virustotal.py`, `test_verdict.py`, `test_jobs.py`, `test_sandbox_files.py`, `test_static.py`, `test_app.py`). `.github/workflows/tests.yml` ile GitHub Actions CI bağlandı.
- **README sadece Türkçe.** — ✅ DÜZELTİLDİ (Gemini): İngilizce `README.md`, mimari diyagramı ve tam yüklenmiş web arayüzünün ekran görüntüsü (`static/screenshot.png`) eklendi. Türkçe döküman `README.tr.md` olarak korundu.
- ~~**Analiz yönetimi**~~ (C11) — A12 ile birlikte yapıldı: silme, iptal, eskileri temizleme.
- **Yeni Sandbox komut satırı.** Windows 11 24H2 ve sonrasında `wsb start`, `wsb exec`, `wsb stop` komutları var. Pencere açıp işlem adından durum tahmin etmek yerine bunlar kullanılırsa başlatma, durum sorma ve kapatma güvenilir olur.
- **Sandbox belleği panelden ayarlanamıyor.** — ✅ DÜZELTİLDİ (Gemini): Panel arayüzüne 2 GB–16 GB RAM seçim kutusu eklendi; backend `pipeline.create_job` ve `sandbox_manager.build_wsb` bellek (1024–65536 MB) ve süre (1–180 dk) değerlerini sınırlandırıp doğrular.
- **Salt okunur klasörden çalışan kurulumlar.** — ✅ DÜZELTİLDİ (Gemini): 1 GB üstü kurulumlar `in-place` çalıştırıldığında `compute_verdict` rapora uyarı ekler; `sanitize_sandbox_json` `RunMode`/`Target` alanlarını stringe zorlayarak tip zehirlenmesini engeller.
- **Ağ kaydı tavanı.** — ✅ DÜZELTİLDİ (Gemini): `Inside-Sandbox.ps1` içindeki `pktmon start` komutuna `--pkt-size 512` eklendi (Windows `pktmon` varsayılanı olan 128 byte'ta HTTP/TLS SNI başlıklarının kesilmesini önlerken tam paketlerin 2 GB kaydı gereksiz şişirmesini 512 byte ile sınırlar). *Not: Çok büyük indirmelerde 2 GB döngüsel tampon hâlâ dolabilir.*
- **Rapor dili ve biçimi.** — ✅ DÜZELTİLDİ (Gemini): HTML (`report.html`) ve JSON (`state.json`) dışa aktarma eklendi. `write_html_report` tüm düz metin, liste, kod/kalın blokları ve tablo linklerini XSS'e karşı temizler (`javascript:` engelli); `report?format=html` betiksiz (`default-src 'none'; style-src 'unsafe-inline'`) CSP ile sunulur.
- **Yerel API'de kimlik doğrulama yok.** — ✅ DÜZELTİLDİ (Gemini): Tüm `/api/*` uç noktaları (`GET` dahil; yalnızca `/api/health` ve `/api/auth` hariç) ve `GET /` rastgele `API_TOKEN` ile korunur; yetkisiz `GET /` token veya çerez sızdırmaz (`401`). `Baslat.bat` `%LOCALAPPDATA%\SafeBox\session.token` üzerinden tek tıkla otomatik oturum açar; tarayıcı/API istekleri `X-SafeBox-Token` ve `HttpOnly; SameSite=Strict` çerezle doğrulanır.

## C. Yeni özellik önerileri

Etkisine göre sıralı.

1. **Bırakılan dosyaların hash'ini VirusTotal'de sorgulamak.** — ✅ YAPILDI (Gemini): `Inside-Sandbox.ps1` yeni çalıştırılabilirlerin (`NewExecutables`) SHA-256 hash'lerini toplar (`DroppedHashes`); `_check_dropped_files_vt` 64 hane hex doğrulaması yapıp büyük/küçük harfi normalize ederek tekilleştirir ve en fazla 10 yeni hash'i dosya yüklemeden VT'de sorgular.
2. **Kurulum paketlerinin içini açmak.** — ✅ YAPILDI (Gemini): `pipeline._unpack_installers` / `_unpack_one_installer`, 7-Zip (`Nsis`, `Compound`/MSI, `.cab`, `7z`/`zip`/`Rar` SFX) kurulum paketlerini boyut/bomba kontrolü altında `case_dir/unpacked` klasörüne açar; `input/` sandbox için temiz kalırken çıkarılan dosyalar `[paket içi]` etiketiyle imza, statik ve VT envanterine dahil edilir (yalnızca `PE` olan düz binary'ler açılmaz).
3. **YARA kuralları.** — ✅ YAPILDI (Gemini): `rules/safebox_builtin.yar` içinde 6 yüksek sinyalli YARA kuralı ve `yara_scanner.py` (`yara-python` varsa yerel motoru, yoksa yerleşik offline `.yar` ayrıştırıcısını kullanan ikili motor) eklendi. `analyzer.analyze_single_file`, `app.py` (`/api/system-status`), `pipeline.write_report` ve `static/app.js` YARA eşleşmelerini raporlar. (`rules/` klasörüne ek `.yar` dosyaları bırakılabilir).
4. **Ekran görüntüleri.** — ✅ YAPILDI (Gemini): `Inside-Sandbox.ps1` izleme sırasında 30 saniyede bir (başlangıç ve bitiş dahil, en fazla 24 kare) `output/screenshots/scr_NNN.png` yakalar. `pipeline.quarantine_output` yalnızca gerçek PNG+IHDR başlıklı (`<= 10 MB`, max 30 dosya) `scr_NNN.png` karelerine izin verip sahte dosya/exe denemelerini `.quarantine` yapar. Panelde canlı galeri ve `/api/jobs/{id}/screenshots/{name}` ucu eklendi.
5. **Sahte kullanıcı hareketi.** — ✅ YAPILDI (Gemini): Panel ve `JobRequest` içine `simulate_user` seçeneği eklendi ve `tools/config.json` (`SimulateUser`) üzerinden sandbox içine aktarılır. `Inside-Sandbox.ps1` içindeki `Invoke-FakeUser` (`saf ASCII`, PS 5.1) fare imlecini periyodik hareket ettirir ve UI Automation (`UIAutomationClient`) ile yalnızca örnek işlem ağacındaki (`$TreePids`) pencerelerde `Next / İleri / Install / Yükle / Kabul / Finish / OK` düğmelerine tıklar (kendi konsoluna veya sistem pencerelerine dokunmaz).
6. **Bağlantıları işlemle eşlemek.** — ✅ YAPILDI (Gemini): `pipeline.correlate_network_processes` ve geliştirilen `network_summary`, tshark DNS yanıt IPlerini (`dns.a`/`dns.aaaa`), `DnsCache` kayıtlarını ve TLS SNI / HTTP paket hedef `(IP, Port)` bilgilerini Sandbox `Connections` tablosuyla eşleştirir. DNS/SNI/HTTP/TCP özetlerinde, `report.md`/`report.html` içinde ve web panelinde (`static/app.js`) bağlantıyı açan işlem adı ve `[örnek]` etiketi gösterilir.
7. **İki çalıştırmayı karşılaştırmak.** — ✅ YAPILDI (Gemini): `pipeline.compare_jobs`, `/api/compare?base=...&target=...` ve paneldeki `⚖️ Karşılaştır` penceresi ile resmi kurulum ve crack'li/şüpheli sürüm arasındaki eklenen/değişen dosya hash & imza bozulmaları, statik risk/YARA artışları, ekstra kalıcılık (Servis/Görev/Run/Defender/Firewall) ve ek ağ alan adı/IP farkları özetlenir.
8. **Göstergeleri dışa aktarmak.** — ✅ YAPILDI (Gemini): `pipeline.collect_iocs`, `export_iocs_csv` ve `export_iocs_stix` ile SHA-256, alan adı, IPv4/IPv6 ve URL göstergeleri Microsoft/yerel gürültüsünden arındırılarak (ve CSV formül enjeksiyonuna karşı korunarak) CSV veya STIX 2.1 paketi olarak dışa aktarılır. `/api/jobs/{id}/iocs?format=csv|stix` ucu ve arayüz indirme düğmeleri (`🧾 IOC (CSV)`, `🛡 IOC (STIX 2.1)`) eklendi.
9. **Ek istihbarat kaynakları.** — ✅ YAPILDI (Gemini): `intel_client.py` ile MalwareBazaar (`mb-api.abuse.ch`) ve Hybrid Analysis (`hybrid-analysis.com/api/v2/overview`) üzerinden yalnızca SHA-256 hash sorgusu (dosya yüklemeden) eklendi. VT anahtarı olmadığında veya VT kotası dolduğunda `stage_vt` içinde otomatik yedek olarak çalışır; `/api/intel/config`, `/api/intel/query/{sha256}`, dosya kartlarında `🔍 MB / HA Sor` butonu ve modal ayarları eklendi. (`compute_verdict` tespitleri kırmızı/sarı bulguya işler).
10. **Bildirim.** Analiz bitince ya da kırmızı bayrak çıkınca Windows bildirimi. Uzun izlemelerde panelin başında beklemek gerekmez.
11. **Analiz yönetimi.** Paneldan analiz silme, iptal etme ve "30 günden eskileri temizle" seçeneği (A12'deki iki maddeyi çözer).
12. **Sağ tık menüsü.** Dosya Gezgini'nde "wsb-triage ile analiz et" seçeneği. Paneli açıp yol seçmekten hızlı.

## Önerilen sıra

1. Sandbox'ı açıp gerçek bir uçtan uca deneme yapmak, çıkan sorunları düzeltmek.
2. ~~A1 ve A2~~ — düzeltildi.
3. ~~A3–A12~~ — düzeltildi (A12'deki Defender maddesi gerçek Sandbox denemesini bekliyor).
4. Testleri depoya taşımak ve CI kurmak. Sonraki değişiklikler güvenle yapılır.
5. C1 (bırakılan dosyaların hash sorgusu) ve C3 (YARA). A9 düzeltildi; YARA statik adımı daha da isabetli yapar.
6. Tailwind'i yerelleştirip CSP eklemek, İngilizce README.

---

## Gemini Geliştirme, Denetim ve Düzeltme Özeti

Bu bölüm, Gemini tarafından yapılan tüm değişikliklerin sonradan tek tek incelenebilmesi için adım ve commit özetini içerir.

### 1. İlk Uygulama Adımları (Gemini)

- **`746f9b9` — B2 (Test paketi & GitHub Actions CI):** Geçici testler `tests/` (`test_extract.py`, `test_virustotal.py`, `test_verdict.py`, `test_jobs.py`, `test_sandbox_files.py`, `test_static.py`, `test_app.py`) altına taşındı; `pytest.ini`, `requirements-dev.txt` ve `.github/workflows/tests.yml` eklendi.
- **`cd2ccd4` — B1 (İlk Tailwind & CSP adımı):** Harici CDN betiği `static/tailwind.js` olarak indirildi, `app.py` ara katmanına ilk CSP ve güvenlik başlıkları kondu. *(Daha sonra `8c7c850` ile gerçek statik CSS + sıkı CSP'ye dönüştürüldü.)*
- **`580142f` — C1 (Bırakılan dosya hash sorgusu):** `sandbox/Inside-Sandbox.ps1` içinde `NewExecutables` için SHA-256 toplama (`DroppedHashes`) ve `pipeline.py` içinde `_check_dropped_files_vt` eklendi.
- **`0443baf` — B9 (İlk API belirteci adımı):** `app.py` içine `API_TOKEN` üretimi ve mutating `POST/DELETE` uçlarına token kontrolü eklendi. *(Daha sonra `8c7c850` ile tüm `/api/*` uçlarını ve `GET /` erişimini kapsayacak şekilde düzeltildi.)*
- **`9c298e9` — B5 & B8 (Bellek seçimi & HTML/JSON rapor):** `static/index.html` bellek seçicisi (`2048`–`16384` MB), `sandbox_manager.build_wsb` parametresi, `pipeline.write_html_report` ve `/api/jobs/{id}/report?format=html|json` eklendi.
- **`960b69a` — B3 (İngilizce README & ekran görüntüsü):** `README.md`, `README.tr.md` ve `static/screenshot.png` eklendi.
- **`18a9e49` — B6 & B7 (`in-place` uyarısı & `pktmon` paket boyutu):** `pipeline.compute_verdict` içine salt okunur `in-place` uyarısı, `Inside-Sandbox.ps1` içine `--pkt-size 512` parametresi eklendi.
- **`4255110` — İlk `fable.md` güncellemesi.**

### 2. İkinci Tur Denetimde Bulunan Yanlışlar ve Yapılan Düzeltmeler (`8c7c850` — Gemini)

Gemini imzalı önceki adımlar tek tek denetlendiğinde tespit edilen hatalar ve uygulanan düzeltmeler:

1. **B9 — Token sızıntısı ve eksik `GET` koruması (`app.py`, `Baslat.bat`, `static/auth.html`, `static/auth.js`, `static/app.js`):**
   - *Bulunan hata:* `GET /` kimlik doğrulaması olmadan `API_TOKEN` değerini HTML içine yazıp çerez veriyordu; `GET /api/*` uçları (`/api/browse-dialog`, `/api/jobs`, `/api/jobs/{id}/report`, `/api/system-status`, `/api/vt/query/{sha}`) hiç token sormuyordu. Boş `X-SafeBox-Token` başlığı gönderildiğinde çereze düşülüyordu (`or`). Paneldeki `bReport` butonu ham `fetch` kullandığı için token göndermiyordu.
   - *Düzeltme:* Yetkisiz `GET /` artık `401` ile [auth.html](static/auth.html) kilit ekranını açar (HTML/çerez sızdırmaz). `GET /api/health` ve `POST /api/auth` dışında **tüm `/api/*` uçları (`GET` dahil)** token zorunlu kılar. `Baslat.bat`, sunucu açılışında `%LOCALAPPDATA%\SafeBox\session.token` dosyasını okuyup `/?token=...` → `303` yönlendirmesiyle tek tıkla `HttpOnly; SameSite=Strict` çerez başlatır; `bReport` ve tüm API istekleri `X-SafeBox-Token` gönderir.
2. **B1 — Etkisiz CSP ve çalışma zamanı Play CDN betiği (`app.py`, `static/index.html`, `static/styles.css`, `static/app.js`):**
   - *Bulunan hata:* CSP `script-src 'self' 'unsafe-eval' 'unsafe-inline'` ve `style-src 'self' 'unsafe-inline'` içerdiğinden XSS'e karşı ikinci katman sağlamıyordu; `static/tailwind.js` çalışma zamanı JS derleyicisi olduğu için Edge konsolunda üretim uyarısı veriyordu ve `/favicon.ico` 404 hatası oluşuyordu. (`app.py` upload kontrolünde yinelenen erişilemez `return` satırı vardı.)
   - *Düzeltme:* `static/tailwind.js` silindi; tüm sınıflar önceden statik [styles.css](static/styles.css) dosyasına derlendi, satır içi `<script>` ve `<style>` kaldırılarak [app.js](static/app.js) ayrıldı (`<meta name="safebox-token">` kullanımı). CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none';` ve `Cache-Control: no-store` olarak sıkılaştırıldı; `<link rel="icon" href="data:," />` eklendi.
3. **B8 — `write_html_report` Stored XSS ve Markdown hatası (`pipeline.py`, `app.py`, `static/app.js`):**
   - *Bulunan hata:* `- ` ve paragraf satırlarındaki düz metinlerde HTML escape yapılmıyordu (zararlı dosya/komut adları `report.html` içine ham HTML/JS basabiliyordu); `` **`kod`** `` birleşiminde çift escape oluyordu; `<li>` etiketleri `<ul>` olmadan basılıyordu; tablo linkleri `javascript:` şemasını engellemiyordu ve HTML rapor linklerinde `rel="noopener"` eksikti.
   - *Düzeltme:* `_render_inline_md`, `_render_plain_bold`, `<ul>...</ul>` bloklama ve `https?://` link doğrulaması yazıldı. `/api/jobs/{id}/report?format=html` uç noktası betiksiz CSP (`default-src 'none'; style-src 'unsafe-inline'`) ile sunulur.
4. **C1 — `_check_dropped_files_vt` doğrulama ve büyük/küçük harf hatası (`pipeline.py`):**
   - *Bulunan hata:* `DroppedHashes` içinde `SHA256` formatı doğrulanmıyordu (VT yol enjeksiyonu riski), `Path: None` durumunda `TypeError` riski vardı, PowerShell büyük harf / Python küçük harf hash uyuşmazlığı nedeniyle mevcut hash tekrar sorgulanabiliyordu ve döngü 10 ile kırpılmadan ham sayı loglanıyordu.
   - *Düzeltme:* `^[0-9a-f]{64}$` doğrulaması, küçük harf normalizasyonu, döngü içi `seen_shas` tekilleştirmesi, güvenli `Path`/`Size` temizleme ve canlı `job.stage("sandbox", "running", ...)` güncellemesi eklendi.
5. **B7 (`pktmon`) teknik düzeltmesi ve B5/B6 sınır/tip korumaları (`fable.md`, `pipeline.py`, `sandbox_manager.py`):**
   - *Bulunan hata:* Windows `pktmon start help` çıktısı varsayılan `--pkt-size` değerinin zaten **128 byte** olduğunu doğruladı; önceki açıklamada "--pkt-size 512 ile 2 GB taşması önlendi" ifadesi gerçeği ters yansıtıyordu. Ayrıca `memory_mb`/`duration_min` değerleri sınırsızdı ve `sanitize_sandbox_json` `RunMode`/`Target` için string zorlamıyordu.
   - *Düzeltme:* `fable.md` açıklaması düzeltildi; `create_job` ve `build_wsb` `memory_mb` değerini `1024–65536 MB` ve `duration_min` değerini `1–180 dk` aralığına sınırlandırdı; `sanitize_sandbox_json` `_STRS` listesiyle `RunMode`/`Target` tipini güvenceye aldı.
6. **B3 — Eksik yüklenmiş ekran görüntüsü, kesilen UI kutuları ve `README.md` (`static/index.html`, `static/screenshot.png`, `README.md`):**
   - *Bulunan hata:* İlk ekran görüntüsü `/api/system-status` yanıtı gelmeden yakalanmıştı, `sm:grid-cols-4` kutuları metinleri kırpıyordu ve `README.md` mimari diyagramında hizalama hatası vardı.
   - *Düzeltme:* Kontrol ızgarası `sm:grid-cols-2` yapılarak metin kesilmesi giderildi, ekran görüntüsü sistem durumu yüklendikten sonra yeniden alındı ve `README.md` diyagramı/başlatma adımları düzeltildi.

### 3. Doğrulama Durumu (Gemini Son Kontrol)

- **Birim ve API testleri:** `python -m pytest -q` → `109 passed in 28.99s` (B1, B5, B6, B7, B8, B9, C1 regresyon testleri dahil).
- **Canlı tarayıcı testi (Headless Edge + Playwright):** Yetkisiz `401` kilit ekranı, yanlış/doğru token akışı, `/?token=` yönlendirmesi, satır içi `<script>` enjeksiyonunun CSP ile engellenmesi, `0` konsol hatası/uyarısı ve `report?format=html` render'ı doğrulandı.
- **Kalan açık nokta:** Windows Sandbox bu makinede etkinleştirilmediği için (`WindowsSandbox.exe` yok), gerçek Sandbox içi `Inside-Sandbox.ps1` + `pktmon` + Defender denemesi hâlâ manuel açma/yeniden başlatma sonrası test edilmeyi bekliyor.

### 4. Yeni Özellik Uygulamaları (Bölüm C — Gemini)

- **C2 (Kurulum paketlerinin içini açmak — Gemini):** `pipeline._unpack_installers` & `_unpack_one_installer` ile NSIS/MSI/CAB/SFX paketleri `_check_unpacked_size` korumasından geçerek `case_dir/unpacked` içine çıkarılır; iç `.cab` akışları da açılır. `stage_inventory` bunları `[paket içi]` olarak envantere katar. (`tests/test_extract.py`: 28/28 passed).
- **C3 (YARA kuralları — Gemini):** `rules/safebox_builtin.yar` (credential stealer, Defender tampering, ransomware shadow delete, PowerShell hidden download/exec, chat webhook exfil, patch/keygen) + `yara_scanner.py` (`yara-python` varsa onu, yoksa ASCII/wide/hex destekli yerleşik ayrıştırıcıyı kullanır). `analyzer.py`, `app.py`, `pipeline.py` ve `static/app.js` arayüzüne entegre edildi; tüm `.yar` dosyaları `rules/` klasöründen otomatik yüklenir.
- **C8 (Göstergeleri CSV / STIX 2.1 olarak dışa aktarmak — Gemini):** `pipeline.collect_iocs`, `export_iocs_csv`, `export_iocs_stix` ile örnek/çıkarılan hash'ler, ağ alan adları/IP'ler ve şüpheli URL'ler tekilleştirilir, OS gürültüsü varsayılan olarak filtrelenir (`FromSample` LAN bağlantıları korunur) ve CSV formül enjeksiyonu ile STIX kaçışları güvenli biçimde kodlanır. `/api/jobs/{id}/iocs` ucu ve panel indirme düğmeleri eklendi.
- **C6 (Ağ bağlantılarını işlemle eşlemek — Gemini):** `network_summary` tshark sorguları paket `(IP, Port)` + DNS yanıt IP'lerini çıkarır; `correlate_network_processes` bunları `DnsCache` ve `Connections` ile birleştirerek DNS/SNI/HTTP/TCP satırlarına işlem adını (`FromSample` öncelikli) ekler. Arayüz (`renderNetwork`) ve raporlarda gösterilir.
- **C4 (Periyodik sandbox ekran görüntüleri — Gemini):** `Inside-Sandbox.ps1` `Capture-Screen` (30 sn aralıkla PNG, saf ASCII PS 5.1); `pipeline.is_valid_screenshot_file` & `quarantine_output` yalnızca geçerli `scr_NNN.png` (`PNG+IHDR`) dosyalarını kabul eder; `app.py` PNG akışı ve `static/` canlı küçük resim galerisi eklendi.
- **C5 (Sahte kullanıcı hareketi — Gemini):** `pipeline.DEFAULT_OPTIONS["simulate_user"]`, `app.JobRequest`, `static/index.html` (`#optSimUser`) ve `Inside-Sandbox.ps1` `Invoke-FakeUser` eklendi; Win32 fare hareketi (`SetCursorPos`) ve yalnızca örnek PID ağacına ait pencerelerde UIA otomatik kurulum tıklaması yapar. (`test_script_is_ascii` & `test_script_parses` geçti).
- **C9 (MalwareBazaar & Hybrid Analysis ek tehdit istihbaratı — Gemini):** `intel_client.py` (salt hash sorgusu), `stage_vt` yedek entegrasyonu (VT anahtarı yokken veya kota dolduğunda), `compute_verdict` kırmızı/sarı bulguları, `/api/intel/*` uç noktaları ve arayüz ayar/sorgu akışı eklendi.
- **C7 (İki çalıştırmayı karşılaştırmak — Gemini):** `pipeline.compare_jobs`, `/api/compare` API ucu ve arayüz `⚖️ Karşılaştır` penceresiyle resmi vs crack sürüm arasındaki değişen/bozulan imzalı dosyalar, YARA/risk artışları, ekstra kalıcılık kayıtları ve ek dış bağlantılar fark olarak sunulur.
