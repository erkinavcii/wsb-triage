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
2. **Kurulum paketlerinin içini açmak.** 7-Zip, NSIS ve MSI gibi birçok kurulum biçimini açabiliyor. Statik analiz şu an sadece dıştaki `setup.exe`'ye bakıyor. İçindeki dosyalar da envantere girerse imzası bozuk DLL'ler çalıştırmadan görülür.
3. **YARA kuralları.** `yara-python` ile açık kural setleri (örneğin YARA-Forge) statik adıma eklenebilir. A9'daki el yapımı desenlerden çok daha isabetli olur.
4. **Ekran görüntüleri.** İzleme sırasında 30 saniyede bir sandbox ekranının görüntüsü. Sahte kurulum ekranları ve fidye notları tek bakışta anlaşılır.
5. **Sahte kullanıcı hareketi.** Fare hareketi ve "İleri" butonlarına otomatik tıklama. Hem kurulumlar kendiliğinden ilerler hem de hareket bekleyen zararlılar tetiklenir.
6. **Bağlantıları işlemle eşlemek.** Ağ özetinde her alan adının yanında hangi işlemin bağlandığı yazsın. İzleyici bu bilgiyi zaten topluyor, sadece tshark özetiyle birleştirilmiyor.
7. **İki çalıştırmayı karşılaştırmak.** Aynı programın resmi sürümüyle crack'li sürümünü ayrı ayrı çalıştırıp farkı göstermek. Crack'in fazladan ne yaptığı doğrudan ortaya çıkar.
8. **Göstergeleri dışa aktarmak.** Hash, alan adı ve IP listesini CSV ya da STIX olarak vermek.
9. **Ek istihbarat kaynakları.** MalwareBazaar ve Hybrid Analysis hash sorguları ücretsiz. VirusTotal kotası dolduğunda yedek olur.
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
