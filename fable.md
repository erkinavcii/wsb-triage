# wsb-triage — genel inceleme

İlk inceleme: 11 Kasım 2026, commit `cb78e43`. Son güncelleme: 19 Kasım 2026.

Bu belge kodun tamamı okunarak hazırlandı. "Doğrulandı" yazan maddeler kodda ya da küçük bir denemeyle teyit edildi. A bölümünün tamamı, B ve C'nin neredeyse tamamı düzeltildi/yapıldı; her maddenin altında ne yapıldığı yazıyor.

## Durum özeti (24 Kasım 2026)

- **Testler:** **172 test** (`172 passed, 0 skipped, 0 failed` — `python -m pytest -v`) yerelde geçiyor (`18` yerleşik YARA kuralı hem `yara-python` hem yerleşik motorda birebir uyumlu), ayrıca `node --check static/app.js` ve PowerShell 5.1 AST/ASCII kontrolleri temiz.
- **CI:** 13 Kasım'daki son GitHub Actions çalışması **başarısızdı** (`test_signatures_are_read`: imza kontrolü CI makinesinde sessizce "Unknown" dönüyordu). Hata artık görünür ve olası neden giderildi (aşağıda D1); CI'nin yeşile dönüp dönmediği bir sonraki gönderimde görülecek.
- **İkinci inceleme (19 Kasım):** Gemini'nin eklediği B/C değişiklikleri incelendi. Sağlam olanlar: API belirteci, CSP, bildirimler, ekran görüntüsü doğrulaması, sağ tık menüsü, otomatik tıklama, panelde güvenli gösterim. Bulunan dört sorun ve düzeltmeleri **D** bölümünde.
- **Üçüncü inceleme (19–20 Kasım):** Kodda kalan somut hatalar/kopukluklar ve projenin temel amacına (ön tespit + alternatif ortamda çalıştırma) yönelik eksik özellikler **E** bölümüne eklendi ve **E1–E17** tamamlandı.
- **Dördüncü inceleme & canlı repack doğrulaması (24 Kasım):** Gerçek dünya çok katmanlı kurulum testi (`Photoshop.2026`) sonrası saptanan iç içe arşiv / PE yanlış pozitif ve Sandbox yem dosya / yerel ağ gürültüsü sorunları giderildi; ileri seviye statik/istihbarat/dinamik bellek & FakeNet yetenekleri (**F1–F8**) eklendi.

## D. İkinci incelemede bulunanlar (19 Kasım 2026)

### D1. İmza kontrolü sessizce başarısız olabiliyor — ✅ DÜZELTİLDİ

- **Sorun:** PowerShell imza scripti hata verirse (modül yüklenemezse, script çalışmazsa) her dosya sessizce "Unknown", yani imzasız sayılıyordu. CI'de tam olarak bu oldu; kullanıcı bilgisayarında olsaydı raporlar fark edilmeden yanlış olurdu.
- **Düzeltme:** Script hatayı dosya başına "Error" durumu ve mesajıyla yazıyor; script hiç çalışmazsa PowerShell'in kendi hata metni kaydediliyor; envantere uyarı, sonuç kutusuna not düşülüyor. Windows PowerShell 5.1 tam yoluyla ve miras alınan `PSModulePath` olmadan başlatılıyor (PowerShell 7'nin modül yolu karışmasın diye). **Kök neden kesin değil:** `PSModulePath` teorisi yerelde taklit edilerek yeniden üretilemedi; CI bir sonraki çalışmada başarısız olursa test çıktısı artık PowerShell'in hata mesajını gösterecek.

### D2. Ağ kaydı TLS sunucu adlarını kaybedebiliyordu — ✅ DÜZELTİLDİ

- **Sorun:** B7'de `--pkt-size 0` (paketin tamamı) `512`'ye indirilmiş ve bu "kesilmeyi önlüyor" diye belgelenmişti; `pktmon` yardımına göre `0` tam paket, varsayılan 128 bayttır — yani değişiklik kaydı küçültüyordu. Kuantum sonrası anahtarlı TLS ClientHello 1,5–2 KB'tır ve istemciler uzantı sırasını karıştırır; sunucu adı (SNI) 512 baytın dışında kalabilir.
- **Düzeltme:** `--pkt-size 4096`: normal paketler ve TLS el sıkışması tam kalıyor, sadece büyük indirmelerin 64 KB'a varan birleştirilmiş paketleri kırpılıyor. Gerçek sandbox kaydıyla doğrulanmadı.

### D3. YARA kuralları sessizce çalışmayabiliyordu — ✅ DÜZELTİLDİ

- **Sorun:** `yara-python` bağımlılıklarda yoktu, yerleşik ayrıştırıcı kullanılıyordu. Bu ayrıştırıcı tek satırlık, etiketli (`rule X : tag`) ya da `private/global` kuralları hiç görmüyor; hex joker/atlama, regex, `filesize`, `uint16`, `#sayım` kullanan kuralları uyarısız "eşleşmedi" sayıyordu. `yara-python` kuruluyken söz dizimi hatalı tek bir `.yar` dosyası `/api/system-status`'u ve statik analizi çökertirdi.
- **Düzeltme:** `yara-python` `requirements.txt`'e eklendi. Her kural dosyası ayrı derleniyor, bozuk olan atlanıp nedeniyle listeleniyor. Yerleşik motor tek satırlık/etiketli kuralları okuyor, `fullword` destekliyor, çalıştıramadığı kuralı atlayıp nedenini bildiriyor. Panel rozeti yerleşik motor ya da atlanan kural varsa sarı uyarı gösteriyor. Test: depodaki 6 kuralda iki motor birebir aynı sonucu veriyor.

### D4. Bu belge güncel değildi — ✅ DÜZELTİLDİ

- Başlıktaki "Hiçbir madde henüz düzeltilmedi" cümlesi ve CI'nin kırmızı olduğunun yazılmaması düzeltildi (bu bölüm ve yukarıdaki özet).

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
- **Depoda test yok.** — ✅ DÜZELTİLDİ (Gemini): Birim, statik, API ve regresyon testleri `tests/` klasörüne taşındı (`test_extract.py`, `test_virustotal.py`, `test_verdict.py`, `test_jobs.py`, `test_sandbox_files.py`, `test_static.py`, `test_app.py`; C fazı eklemeleriyle toplam 122 test). `.github/workflows/tests.yml` ile GitHub Actions CI bağlandı.
- **README sadece Türkçe.** — ✅ DÜZELTİLDİ (Gemini): İngilizce `README.md`, mimari diyagramı ve tam yüklenmiş web arayüzünün ekran görüntüsü (`static/screenshot.png`) eklendi. Türkçe döküman `README.tr.md` olarak korundu.
- ~~**Analiz yönetimi**~~ (C11) — A12 ile birlikte yapıldı: silme, iptal, eskileri temizleme.
- **Yeni Sandbox komut satırı.** ⏸ *(Kullanıcı isteğiyle şimdilik bekletildi.)* Windows 11 24H2 ve sonrasında `wsb start`, `wsb exec`, `wsb stop` komutları var. Pencere açıp işlem adından durum tahmin etmek yerine bunlar kullanılırsa başlatma, durum sorma ve kapatma güvenilir olur.
- **Sandbox belleği panelden ayarlanamıyor.** — ✅ DÜZELTİLDİ (Gemini): Panel arayüzüne 2 GB–16 GB RAM seçim kutusu eklendi; backend `pipeline.create_job` ve `sandbox_manager.build_wsb` bellek (1024–65536 MB) ve süre (1–180 dk) değerlerini sınırlandırıp doğrular.
- **Salt okunur klasörden çalışan kurulumlar.** — ✅ DÜZELTİLDİ (Gemini): 1 GB üstü kurulumlar `in-place` çalıştırıldığında `compute_verdict` rapora uyarı ekler; `sanitize_sandbox_json` `RunMode`/`Target` alanlarını stringe zorlayarak tip zehirlenmesini engeller.
- **Ağ kaydı tavanı.** — ✅ DÜZELTİLDİ (Gemini; değer D2'de 4096'ya çıkarıldı, aşağıdaki açıklamadaki 512 gerekçesi yanlıştı): `Inside-Sandbox.ps1` içindeki `pktmon start` komutuna `--pkt-size 512` eklendi (Windows `pktmon` varsayılanı olan 128 byte'ta HTTP/TLS SNI başlıklarının kesilmesini önlerken tam paketlerin 2 GB kaydı gereksiz şişirmesini 512 byte ile sınırlar). *Not: Çok büyük indirmelerde 2 GB döngüsel tampon hâlâ dolabilir.*
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
10. **Bildirim.** — ✅ YAPILDI (Gemini): `pipeline.notify_desktop` ve `_maybe_notify_job`, analiz tamamlandığında veya kırmızı bayrak çıktığında (`notify` seçeneği aktifken) sabit PowerShell betiği + ortam değişkenleri üzerinden (komut enjeksiyonuna karşı güvenli, bloklamayan) Windows sistem tepsisi/Action Center bildirimi gönderir; panelde `#optNotify` onay kutusu eklendi.
11. **Analiz yönetimi.** Paneldan analiz silme, iptal etme ve "30 günden eskileri temizle" seçeneği (A12'deki iki maddeyi çözer).
12. **Sağ tık menüsü.** — ✅ YAPILDI (Gemini): `sandbox_manager.set_context_menu` / `context_menu_status` (`HKEY_CURRENT_USER` altında yönetici yetkisi gerektirmeden dosya ve klasörler için `"SafeBox ile analiz et"` kaydı), hafif başlatıcı `enqueue.py`, `/api/context-menu` API ucu ve panel üst barında tek tıkla aç/kapat düğmesi eklendi. Sağ tık otomatik dosya yüklemeden ve sandbox'ı habersiz açmadan ön taramayı başlatıp tarayıcıyı `#job_id` sayfasında açar.

## Önerilen sıra

1. Sandbox'ı açıp gerçek bir uçtan uca deneme yapmak, çıkan sorunları düzeltmek.
2. ~~A1 ve A2~~ — düzeltildi.
3. ~~A3–A12~~ — düzeltildi (A12'deki Defender maddesi gerçek Sandbox denemesini bekliyor).
4. ~~Testleri depoya taşımak ve CI kurmak.~~ — düzeltildi (Gemini).
5. ~~C1 (bırakılan dosyaların hash sorgusu) ve C3 (YARA).~~ — düzeltildi (Gemini).
6. ~~Tailwind'i yerelleştirip CSP eklemek, İngilizce README.~~ — düzeltildi (Gemini).

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

- **Birim ve API testleri:** `python -m pytest -q` → `122 passed in 37.83s` (sıfır atlanan/başarısız test; B1–B3, B5–B9 ve C1–C12 regresyon testleri dahil).
- **Statik CSS & Canlı Tarayıcı Testi (Headless Edge + Playwright):** Tüm HTML/JS sınıfları statik `static/styles.css` içinde doğrulandı (eksik `.block` sınıfı eklendi); canlı yerel sunucuda yetkisiz `401` kilit ekranı, yanlış/doğru belirteç akışı, `/?token=` yönlendirmesi, `YARA (6 kural)` rozeti, sağ tık menü düğmesi (`#btnCtxMenu`), sahte kullanıcı hareketi (`#optSimUser`) ve bildirim (`#optNotify`) seçenekleri, `Karşılaştır` ve `MalwareBazaar / Hybrid Analysis` modalları, `CSV / STIX 2.1` IOC indirme bağlantıları, sıkı CSP ile satır içi `<script>` engellemesi, normal UI akışında `0` konsol hatası/uyarısı ve `report?format=html` render'ı doğrulandı (`static/screenshot.png` güncellendi).
- **Kalan açık noktalar:**
  1. **B4 (`wsb` CLI):** Kullanıcı isteği üzerine (`web cli kalsın şimdilik`) atlandı ve bekletildi.
  2. **Gerçek Windows Sandbox içi deneme:** Bu makinede `WindowsSandbox.exe` etkin olmadığı için gerçek Sandbox açıldıktan/yeniden başlatıldıktan sonra `Inside-Sandbox.ps1` (ekran görüntüsü, sahte kullanıcı hareketi, işlem-ağ eşleme, `pktmon` + `--pkt-size 4096`) ve Defender davranışı canlı doğrulanmayı bekliyor.

### 4. Yeni Özellik Uygulamaları (Bölüm C — Gemini)

- **C2 (Kurulum paketlerinin içini açmak — Gemini):** `pipeline._unpack_installers` & `_unpack_one_installer` ile NSIS/MSI/CAB/SFX paketleri `_check_unpacked_size` korumasından geçerek `case_dir/unpacked` içine çıkarılır; iç `.cab` akışları da açılır. `stage_inventory` bunları `[paket içi]` olarak envantere katar. (`tests/test_extract.py`: 28/28 passed).
- **C3 (YARA kuralları — Gemini):** `rules/safebox_builtin.yar` (credential stealer, Defender tampering, ransomware shadow delete, PowerShell hidden download/exec, chat webhook exfil, patch/keygen) + `yara_scanner.py` (`yara-python` varsa onu, yoksa ASCII/wide/hex destekli yerleşik ayrıştırıcıyı kullanır). `analyzer.py`, `app.py`, `pipeline.py` ve `static/app.js` arayüzüne entegre edildi; tüm `.yar` dosyaları `rules/` klasöründen otomatik yüklenir.
- **C8 (Göstergeleri CSV / STIX 2.1 olarak dışa aktarmak — Gemini):** `pipeline.collect_iocs`, `export_iocs_csv`, `export_iocs_stix` ile örnek/çıkarılan hash'ler, ağ alan adları/IP'ler ve şüpheli URL'ler tekilleştirilir, OS gürültüsü varsayılan olarak filtrelenir (`FromSample` LAN bağlantıları korunur) ve CSV formül enjeksiyonu ile STIX kaçışları güvenli biçimde kodlanır. `/api/jobs/{id}/iocs` ucu ve panel indirme düğmeleri eklendi.
- **C6 (Ağ bağlantılarını işlemle eşlemek — Gemini):** `network_summary` tshark sorguları paket `(IP, Port)` + DNS yanıt IP'lerini çıkarır; `correlate_network_processes` bunları `DnsCache` ve `Connections` ile birleştirerek DNS/SNI/HTTP/TCP satırlarına işlem adını (`FromSample` öncelikli) ekler. Arayüz (`renderNetwork`) ve raporlarda gösterilir.
- **C4 (Periyodik sandbox ekran görüntüleri — Gemini):** `Inside-Sandbox.ps1` `Capture-Screen` (30 sn aralıkla PNG, saf ASCII PS 5.1); `pipeline.is_valid_screenshot_file` & `quarantine_output` yalnızca geçerli `scr_NNN.png` (`PNG+IHDR`) dosyalarını kabul eder; `app.py` PNG akışı ve `static/` canlı küçük resim galerisi eklendi.
- **C5 (Sahte kullanıcı hareketi — Gemini):** `pipeline.DEFAULT_OPTIONS["simulate_user"]`, `app.JobRequest`, `static/index.html` (`#optSimUser`) ve `Inside-Sandbox.ps1` `Invoke-FakeUser` eklendi; Win32 fare hareketi (`SetCursorPos`) ve yalnızca örnek PID ağacına ait pencerelerde UIA otomatik kurulum tıklaması yapar. (`test_script_is_ascii` & `test_script_parses` geçti).
- **C9 (MalwareBazaar & Hybrid Analysis ek tehdit istihbaratı — Gemini):** `intel_client.py` (salt hash sorgusu), `stage_vt` yedek entegrasyonu (VT anahtarı yokken veya kota dolduğunda), `compute_verdict` kırmızı/sarı bulguları, `/api/intel/*` uç noktaları ve arayüz ayar/sorgu akışı eklendi.
- **C7 (İki çalıştırmayı karşılaştırmak — Gemini):** `pipeline.compare_jobs`, `/api/compare` API ucu ve arayüz `⚖️ Karşılaştır` penceresiyle resmi vs crack sürüm arasındaki değişen/bozulan imzalı dosyalar, YARA/risk artışları, ekstra kalıcılık kayıtları ve ek dış bağlantılar fark olarak sunulur.
- **C10 (Windows bildirimi — Gemini):** `pipeline.notify_desktop` ve `_maybe_notify_job` ile analiz sonlandığında/kırmızı bayrak çıktığında sabit PowerShell + ortam değişkenleri kullanan engelleyici olmayan Windows masaüstü bildirimi ve panel onay kutusu (`#optNotify`) eklendi.
- **C12 (Dosya Gezgini sağ tık menüsü — Gemini):** `sandbox_manager.set_context_menu` (`HKCU` altında dosya + klasör kaydı), `enqueue.py` hızlı başlatıcısı, `/api/context-menu` ve üst bar durum/geçiş düğmesi eklendi. (`winreg` mock ile test edildi).

### 5. Son CSS Denetimi ve Dokümantasyon Güncellemesi (Gemini)

- **`static/styles.css`:** Eksik olan `.block { display: block; }` kuralı eklendi; tüm `index.html`, `auth.html` ve `app.js` sınıfları statik olarak doğrulandı.
- **`README.md`, `README.tr.md` & `static/screenshot.png`:** B1–B3, B5–B9 ve C1–C12 özellikleri hem İngilizce hem Türkçe README belgelerine ve güncel ekran görüntüsüne işlendi.

---

## E. Üçüncü İnceleme — Açık Hatalar ve Eksik Özellikler (19–20 Kasım 2026)

Bu bölümdeki açık hata ve eksik özellik maddelerinin (**E1–E17**) tamamı 20 Kasım 2026 tarihinde koda uygulanmış, CSP/CSS uyumluluğu ve **149 testlik** pytest paketiyle doğrulanmıştır (`E7` canlı WSB ve `E8` canlı VirtualBox misafir çalıştırması dışında — bunların kod ve mock testleri tam olup canlı ortam doğrulaması hostta Sandbox özelliğinin açılmasını veya VM misafir oturum bilgilerini beklemektedir).

### 1. Kodda Tespit Edilen Açık Hatalar ve Kopukluklar

- **E1. YARA eşleşmeleri ve yüksek statik risk puanı nihai karara (`verdict`) yansımıyor — ✅ UYGULANDI:**
  - `compute_verdict` artık kritik/yüksek YARA eşleşmelerini, `spoof_flags` (kritik/yüksek), `format_findings` (yüksek/kritik) ve imzasız yüksek statik risk puanlarını (`>= 75` kırmızı, `>= 65` sarı not) doğrudan karara işliyor (`tests/test_verdict.py` ile doğrulandı).
- **E2. IOC dışa aktarmada statik SHA-256 yanlış anahtardan okunuyor — ✅ UYGULANDI:**
  - `collect_iocs`, `st.get("sha256") or (st.get("hashes") or {}).get("sha256")` ile statik sonuçtaki gerçek iç içe SHA-256 hash'ini ve `interesting_ips` IPv4 IOC'lerini CSV/STIX 2.1 çıktısına aktarıyor (`tests/test_verdict.py` ile doğrulandı).
- **E3. Sandbox'ın topladığı 3 yüksek sinyalli davranış alanı kullanılmıyor — ✅ UYGULANDI:**
  - `Files.ModifiedExecutables`, `Network.NewListening` ve `Hosts.Removed` artık `compute_verdict`, `write_report`, `compare_jobs` ve `static/app.js` sandbox panelinde tam olarak işleniyor (`tests/test_verdict.py` ile doğrulandı).
- **E4. Statik dosya kartlarındaki VirusTotal rozetleri canlı güncellenmiyor — ✅ UYGULANDI:**
  - `static/app.js` içinde `renderedStaticKey` VT durum/sonuç özetini de içeriyor; VT sorguları tamamlandığında statik dosya kartları sayfa yenilenmeden anında güncelleniyor.
- **E5. Sandbox'ta bırakılan (`DroppedHashes`) dosyalar MalwareBazaar / Hybrid Analysis yedeğine düşmüyor — ✅ UYGULANDI:**
  - `_check_dropped_files_vt` artık VT anahtarı yokken, VT'de kayıt bulunamadığında veya VT kotası dolduğunda `intel_client.query_hash_intel` (MalwareBazaar / Hybrid Analysis) yedeğini çalıştırıyor (`tests/test_virustotal.py` ile doğrulandı).
- **E6. Küçük kod ve arayüz tutarsızlıkları — ✅ UYGULANDI:**
  - `extract_interesting_ips` eklendi (sürüm dizgelerini ve yerel/bogon adresleri filtreleyip ham C2 IP:port çıkarır); PE `architecture`, `compile_time` (`IMAGE_DEBUG_TYPE_REPRO` desteğiyle), `sections` (bölüm entropileri/RWX) ve `total_imports` panelde ve raporda gösteriliyor; `analyzer.scan_path` zip-slip/boyut koruması eklendi; API Ayarları penceresi maskelenmiş VT/MB/HA anahtarlarını ve temizleme düğmelerini (`clear_vt`/`clear_mb`/`clear_ha`) destekliyor; `simulate_user` varsayılanı frontend ve backend'de `True` olarak eşlendi (`tests/test_static.py`, `tests/test_app.py`).

### 2. Alternatif Ortamda Çalıştırma & Dinamik Analiz Eksikleri

- **E7. Gerçek Windows Sandbox uçtan uca doğrulaması ve `wsb.exe` CLI (Windows 11 24H2/25H2) — ✅ KOD & TESTLER TAMAMLANDI (canlı ortam beklemede):**
  - `sandbox_manager.py` içine `wsb_cli_path`, `windows_sandbox_available`, `wsb_list_ids` (JSON + metin ayrıştırma) ve `wsb start --config` destekli `launch_sandbox` / oturum ID bazlı `stop_sandbox` eklendi; mock testleri geçiyor (`tests/test_sandbox_files.py`). Bu makinede `windows_sandbox_enabled: False` olduğu için canlı Sandbox uçtan uca çalıştırması özelliğin etkinleştirilip yeniden başlatılmasını bekliyor.
- **E8. VirtualBox (alternatif VM) çalıştırma arka ucu — ✅ KOD & TESTLER TAMAMLANDI (canlı ortam beklemede):**
  - `sandbox_manager.py`, `pipeline.py`, `app.py` ve web arayüzüne `vbox` arka ucu eklendi: snapshot listeleme (`/api/vbox/snapshots/{vm}`), temiz snapshot geri yükleme, pano/sürükle-bırak/USB izolasyonu, geçici paylaşılan klasörler (`sb_input`, `sb_tools`, `sb_output`), `guestcontrol` üzerinden `Inside-Sandbox.ps1` çalıştırma ve bitişte VM kapatıp snapshot'a döndürme; `vbox_password` yalnızca bellek içi `Job` nesnesinde tutulur (`state.json`/API'ye asla yazılmaz). Mock testleri geçiyor (`tests/test_sandbox_files.py`); canlı VM testi için misafir oturum bilgisi olan kurulu bir Windows VM gereklidir.
- **E9. Sonradan Sandbox başlatırken hedef ve seçenek belirlenemiyor — ✅ UYGULANDI:**
  - `list_runnable_targets` + `/api/jobs/{id}` (`runnable_targets`) + `/api/jobs/{id}/sandbox` (`SandboxStartRequest` geçersiz kılmaları) ve panelde *"Sandbox Ayarlarını Seç ve Başlat"* modalı eklendi (`tests/test_app.py`).
- **E10. Desteklenmeyen çalıştırma dosya türleri ve CLI argümanı eksikliği — ✅ UYGULANDI:**
  - `Inside-Sandbox.ps1` ve hedef seçicisi `.dll` (`rundll32.exe` / `regsvr32` + isteğe bağlı export adı), `.vbe`, `.jse`, `.wsf`, `.pif`, `.jar`, `.reg` uzantılarını, özel CLI argümanlarını (`TargetArgs`) ve standart kullanıcı (`runas.exe /trustlevel:0x20000`) seçeneğini destekliyor (`tests/test_sandbox_files.py`).
- **E11. LAN engelinde `$gw` istisnası ve Sandbox içi yönetici yetkisi riski — ✅ UYGULANDI:**
  - `Inside-Sandbox.ps1` içinde `$gw` genel LAN muafiyetinden çıkarıldı; özel ağdaki DNS IP'leri için yalnızca port 53 açık bırakılıp `1-52, 54-65535` TCP/UDP portları `SafeBox-BlockDNS-TCP` / `SafeBox-BlockDNS-UDP` ile engellendi; `fe80::/10` IPv6 link-local engeli eklendi; `RunAsStandardUser` seçeneği eklendi (`tests/test_sandbox_files.py`).
- **E12. Dinamik izleme kör noktaları — ✅ UYGULANDI:**
  - Döngü 1 sn yoklamaya çekildi; Event ID 4688 komut satırı denetimi (`Import-AuditProcesses`), belge/cüzdan honeyfile yemleri (`Initialize-Honeyfiles` / `Check-Honeyfiles`), `Documents` tarama yolu, gizlenmiş pencere başlığı (`Windows Update Service`) + rastgele fare hareketi, WMI abonelikleri/COM hijacking/`AppInit_DLLs`/BITS/PowerShell profilleri/ActiveSetup, UDP/QUIC SNI ve DoH tespiti, bırakılan dosyalarda imza/entropi/bayrak kontrolü ve `procmon_summary.json` çıkarımı eklendi (`tests/test_verdict.py`, `tests/test_sandbox_files.py`, `tests/test_app.py`).

### 3. Çalıştırmadan Önce Tespit (Statik Analiz) Eksikleri

- **E13. .NET (CLR) zararlıları için analiz eksikliği — ✅ UYGULANDI:**
  - `is_dotnet` (CLR veri dizini kontrolü) ve `_analyze_dotnet_strings` (Reflection yükleme, P/Invoke bellek müdahalesi, DPAPI tarayıcı/cüzdan çözme, ConfuserEx vb. obfuscator izleri) eklendi (`tests/test_static.py`).
- **E14. PE yapısal anomalileri ve 25 MB okuma sınırı — ✅ UYGULANDI:**
  - `imphash`, gerçek sıfır olmayan TLS callback işaretçisi, `DELAY_IMPORT`, RWX bölüm bayrakları, `VirtualSize >> RawSize`, anormal giriş noktası bölümü, düşük import sayısı, `IMAGE_DIRECTORY_ENTRY_SECURITY` hariç tutulan overlay/file-pumping analizleri ve 25 MB üzerindeki dosyalarda son 4 MB kuyruk (tail) string/YARA/PyInstaller/Inno taraması eklendi (`tests/test_static.py`).
- **E15. Script deobfuscation ve güvenli kod/metin/hex önizleyici eksikliği — ✅ UYGULANDI:**
  - `deobfuscate_script` (PowerShell `-enc` Base64 UTF-16LE/UTF-8 ve Batch `^` kaçış temizliği; çözülen komutları string/YARA/URL/IP taramasına geri besler) ve yol dışına taşmayı engelleyen `/api/jobs/{id}/preview` (Metin / Dizge / Hex önizleme penceresi) eklendi (`tests/test_static.py`, `tests/test_app.py`).
- **E16. Ek zararlı dosya/paket biçimleri ve uzantı kandırmacası tespiti — ✅ UYGULANDI:**
  - Saf Python `parse_lnk` (MS-SHLLINK + LOLBin tespiti), OOXML/OLE2 makro/harici `.rels`/gömülü çalıştırılabilir incelemesi, PDF `/Launch`/`/OpenAction`/`/JavaScript` taraması, `_unpack_asar` Electron ASAR açıcı (path-traversal korumalı), Inno Setup desteği ve `detect_spoofing` (RLO `U+202E`, çift uzantı, `MZ` başlıklı sahte belge/medya) eklendi; belgelerin (`.pdf` vb.) gizlilik gereği VT'ye yüklenmeme garantisi korundu (`tests/test_static.py`, `tests/test_extract.py`, `tests/test_virustotal.py`).
- **E17. YARA kural kapsamı ve arayüz yönetimi — ✅ UYGULANDI:**
  - `rules/safebox_builtin.yar` 16 yerleşik kurala çıkarıldı (Crypto Miner, Reverse Shell PS, LSASS Dump, AMSI/ETW Bypass, Office Macro, PDF Action, Clipboard Hijacker, WMI Subscription, UAC Bypass, .NET Loader eklendi); `yara_scanner.py` içindeki dize içi `//` yorum kesme ve motor önbellek anahtarı hataları düzeltildi; `safebox_builtin.yar` salt-okunur korunarak özel `.yar` kural CRUD API'si (`/api/yara/rules*`) ve panel yöneticisi eklendi (`tests/test_static.py`, `tests/test_app.py`).

### 4. Uygulama Durumu Özeti

- Tüm **E1–E17** maddeleri uygulanmış ve test kapsamına alınmıştır. Kalan tek ortam bağımlı adım, hedef makinede isteğe bağlı olarak Windows Sandbox özelliğini etkinleştirmek (`E7`) ve/veya temiz bir VirtualBox Windows VM snapshot'ı hazırlamaktır (`E8`).

---

## F. Dördüncü İnceleme & Gerçek Dünya Paketi Sonrası Geliştirmeler (24 Kasım 2026)

Canlı çok katmanlı kurulum/repack incelemesi (`Photoshop.2026` klasörü -> `5.7 GB .iso` -> alt `.zip` paketleri) sırasında tespit edilen boşluklar ve eklenen yeni yetenekler:

- **F1. Binary PE Dosyalarda "Batch Caret (`^`)" Yanlış Pozitifi Giderildi — ✅ UYGULANDI:**
  - `analyzer.deobfuscate_script(text, allow_caret=True)` satır bazlı doğrulama (`<= 4096` karakter, en az 4 `^` ve en az 3 `^[A-Za-z0-9]` dizilimi + komut anahtar kelimesi) kullanacak şekilde sıkılaştırıldı; `analyze_single_file` içinde PE ikili dosyalar için `allow_caret=False` geçilerek temiz `.exe`/`.dll` dosyalarındaki rastgele `^` karakterlerinin yanlış pozitif üretmesi engellendi (`tests/test_static.py`).
- **F2. PE `VS_VERSIONINFO` Çıkarımı ve Üretici/Sistem Dosyası Kimlik Sahtekarlığı Tespiti — ✅ UYGULANDI:**
  - `analyze_pe_file` artık `StringFileInfo` (`CompanyName`, `ProductName`, `OriginalFilename`, `FileVersion` vb.) bilgisini `pe_info["version_info"]` altına çıkarıyor; geçerli imzası olmadan Microsoft/Adobe/Google/Apple/NVIDIA/Intel/Mozilla olduğunu iddia eden (`vendor_impersonation`) veya `svchost.exe`/`lsass.exe` gibi sistem dosyalarının `OriginalFilename` değerini taşıyıp farklı isimle gizlenen (`sysbin_masquerade`) dosyalar `spoof_flags` ile yakalanıyor (`tests/test_static.py`).
- **F3. MSI `CustomAction`, Kurulum/Lisans Müdahale Betiği (`.pimx`/`.iss`/`RunOnce`) ve 18 Yerleşik YARA Kuralı — ✅ UYGULANDI:**
  - `inspect_msi_file` (`.msi` içi şüpheli `CustomAction` LOLBin/PowerShell tespiti) ve `inspect_installer_config` (`.pimx`, `.iss`, `.inf`, `.ini`, `RunOnce*`, `Patch_*.log` içinde servis/zamanlanmış görev silme ve lisans servisi müdahalesi tespiti) eklendi. `rules/safebox_builtin.yar` içine `SafeBox_License_Service_Tamper` ve `SafeBox_Process_Hollowing_APIs` eklenerek yerleşik YARA kural sayısı **18**'e çıkarıldı (`tests/test_static.py`).
- **F4. Anahtarsız (Zero-Config) Hash İstihbaratı: CIRCL `hashlookup` (NSRL) ve ThreatFox — ✅ UYGULANDI:**
  - `intel_client.py` içine ücretsiz ve API anahtarsız çalışabilen **CIRCL Hashlookup** (`known_good` NSRL bilinen temiz yazılım doğrulaması + `KnownMalicious` kontrolü) ve **ThreatFox IOC** hash sorgusu eklendi; API Ayarları penceresinden (`chkCirclEnabled`, `chkTfEnabled`) tek tıkla etkinleştirilebiliyor (`tests/test_intel.py`, `tests/test_app.py`).
- **F5. Akıllı Kurulum Tıklayıcı (`RadioButton`/`CheckBox`), Canlı Süreç Bellek Taraması (`MemoryFindings`) ve FakeNet Tuzağı — ✅ UYGULANDI:**
  - `sandbox/Inside-Sandbox.ps1` içinde `Invoke-FakeUser`, reklam/bundleware kutularından kaçınarak lisans kabul `RadioButton` (`SelectionItemPattern`) ve `CheckBox` (`TogglePattern`) kontrollerini işaretleyip `Hyperlink`/erişilebilirlik/fare tıklaması yedekleriyle kurulum sihirbazlarını ilerletiyor (`AutoClicks`). Gözlem sonunda örnek süreç ağacı kapanmadan `SafeBoxMem` (`VirtualQueryEx` + `ReadProcessMemory`) ile canlı RAM bölgelerinde şifresi çözülmüş fileless/unpacked C2 ve stealer izleri taranıyor (`MemoryFindings`). İsteğe bağlı `FakeNet` modu ağ kapalıyken `127.0.0.1:53` (DNS) ve `127.0.0.1:80` (HTTP) dinleyerek zararlıların çevrimdışı C2 isteklerini yakalıyor (`FakeNetRequests`) (`tests/test_sandbox_files.py`).
- **F6. Klasör İçi Arşiv ve Seçici İç İçe Arşiv Çıkarımı (`_unpack_nested_archives`) — ✅ UYGULANDI:**
  - `pipeline.py` artık hem doğrudan verilen klasörlerin içindeki arşivleri (`.iso`, `.zip`, `.rar`, `.7z` vb.) hem de arşiv içinden çıkan alt arşivleri (`max_depth=2`) salt okunur girdi klasörüne dokunmadan `unpacked/` altına çıkarıyor. Küçük alt arşivler (`<= 32 MB`) tam açılırken, çok gigabaytlık dev arşivlerde (`> 32 MB`) tüm medya dosyalarını açmak yerine merkezi dizin / `7z l -slt` taranarak yalnızca ana çalıştırılabilirler, script'ler, `.pimx`/`.iss` yapılandırmaları ve yama/crack dosyaları seçilerek çıkarılıyor (`tests/test_extract.py`).
- **F7. Karar Motoru, Rapor, IOC ve Web Arayüzü Entegrasyonu — ✅ UYGULANDI:**
  - `MemoryFindings`, `FakeNetRequests`, `AutoClicks`, `pe_info.version_info` ve CIRCL/ThreatFox sonuçları `compute_verdict`, `write_report`, `collect_iocs`, `compare_jobs` ve sıkı CSP uyumlu web arayüzüne bağlandı (`tests/test_verdict.py`, `tests/test_app.py`).
- **F8. Honeyfile `LastAccessTimeUtc` ve Sandbox Ağ Gürültüsü (`.mshome.net` / WPAD / SSDP) Yanlış Pozitifleri Giderildi — ✅ UYGULANDI:**
  - `sandbox/Inside-Sandbox.ps1` içinde Windows Defender ve Search Indexer'ın tetiklediği `fsutil disablelastaccess 0` / `LastAccessTimeUtc` kontrolü kaldırıldı; yerine yerel dilden bağımsız `S-1-1-0` (`Everyone`) `FileSystemAuditRule` SACL + Security Event ID `4663` süreç doğrulamalı okuma denetimi (`HoneyBenignReaders` istisnalı) eklendi. `pipeline.py` içinde `*.mshome.net`, `wpad.*`, noktasız NetBIOS adları ve yerel/multicast IP'ler (`239.255.255.250:1900` SSDP `M-SEARCH`/`NOTIFY` dahil) `Yerel (gürültü)` olarak sınıflandırılıp filtrelendi (`tests/test_sandbox_files.py`, `tests/test_verdict.py`).

## G. Gerçek Photoshop analizlerinden çıkan düzeltmeler (24 Kasım 2026)

> **Gerçek sandbox doğrulaması:** Sadece `.iso` + sağlama dosyaları içeren zararsız bir test klasörü (ISO'da `Adobe 2026\Set-up.bat`) uçtan uca analiz edildi: ISO ana bilgisayarda açıldı, sandbox'ta `Set-up.bat` bulunup çalıştırıldı, işlemleri (`cmd.exe` → `PING.EXE`) örnekten diye izlendi, sandbox kendiliğinden kapandı, sonuç **yeşil** (kırmızı/not yok, tüm adımlar çalıştı). Bu süreçte G5–G7 gerçek çalıştırmalarda bulunup düzeltildi.

Bu bilgisayardaki gerçek sandbox analizleri incelendi. Bulunan dört sorun ve düzeltmeleri:

- **G1. Sandbox'ta hiçbir şey çalışmadığında sonuç yeşil çıkıyordu — ✅ DÜZELTİLDİ.**
  - *Sorun:* `...Multilingual.md5` analizi 0 baytlık bir sağlama dosyasıydı; sandbox açıldı ama çalıştırılacak dosya yoktu (`behavior.Target` boş) ve sonuç **yeşil** çıktı.
  - *Düzeltme:* `compute_verdict`, sandbox adımı bitmiş ama hedef boşsa "çalıştırılacak dosya bulunamadı, davranış incelenmedi" notu düşüyor ve `not_run` listesine `Sandbox` ekliyor; sonuç artık yeşil olamıyor. Sandbox'ın açıklaması (`TargetNote`) nota ekleniyor.
- **G2. Klasör içindeki ISO sandbox'ta çalışmıyordu — ✅ DÜZELTİLDİ.**
  - *Sorun:* `Photoshop.2026` klasöründe sadece `.iso` ve sağlama dosyaları var. Statik analiz ISO'nun içini açıyordu, ama sandbox klasörü olduğu gibi alıyor ve ISO'yu bağlamıyordu; kurulum hiç çalışmazdı.
  - *İlk deneme (başarısız, gerçek sandbox'ta görüldü):* ISO'yu sandbox içinde `Mount-DiskImage` ile bağlamak. Komut hata vermiyor ama Windows Sandbox'ta hiçbir birim (volume) oluşmuyor; `mountvol` ile harf atama da bu yüzden mümkün olmadı. Bu kod yedek olarak duruyor.
  - *Düzeltme:* Örnekte çalıştırılabilir dosya yoksa ama `.iso`/`.img` varsa, en büyük görüntü **ana bilgisayarda 7-Zip ile** vaka klasörüne açılıyor (`image_root/`, boş alan ve zip bombası kontrolüyle; hiçbir şey çalıştırılmıyor) ve sandbox'a orijinal klasör yerine bu içerik salt okunur bağlanıyor (`pipeline._prepare_image_input`). Kullanıcının klasörüne dokunulmuyor. Ne yapıldığı analiz günlüğüne, başarısızlık nedeni sonuç notuna yazılıyor.
- **G3. Birden fazla dosya ya da klasör sürüklenince sadece ilki alınıyordu — ✅ DÜZELTİLDİ.**
  - *Sorun:* Sürükle-bırak `e.dataTransfer.files[0]` alıyordu; klasör sürüklenince alfabetik ilk dosya (`.md5`, `.sfv`) uyarısız analiz edildi — G1'deki yanlış yeşil sonucun asıl nedeni buydu.
  - *Düzeltme:* Bırakılan klasörlerin içi gezilip (`webkitGetAsEntry`) bütün dosyalar klasör yapısıyla `uploads/batch_<id>/` altına yükleniyor ve **tek analiz** olarak başlatılıyor; dosya seçicide de çoklu seçim var. Bir dosya ya da toplam 4 GB'ı aşarsa **hiçbiri yüklenmiyor** ve kullanıcı "📁 Klasör" butonuna yönlendiriliyor (kısmi yükleme, G1'deki gibi yanlış bir analiz üretirdi). Sunucu göreli yolları temizliyor (`..`, sürücü harfi, geçersiz karakter), hedefin grup klasörünün içinde kaldığını doğruluyor ve grubun toplam boyutunu sınırlıyor. Analiz silinince grup klasörü de siliniyor.
- **G4. Crack'e özgü davranışlar "virüs" gibi kırmızı çıkıyordu — ✅ DÜZELTİLDİ.**
  - *Sorun:* Klasör analizinde "Sahte üretici kimliği" (Adobe yazan imzasız `Set-up.exe`) ve "Lisans müdahale betiği" (Adobe lisans servislerini durduran `.cmd`) kırmızıydı; ikisi de crack'in beklenen işi.
  - *Düzeltme:* Sonuca ayrı bir **"Crack / lisans müdahalesi"** listesi (`verdict.crack`, panelde turuncu, raporda `CRACK/LİSANS`) eklendi; tek başına kırmızıya yol açmıyor. İçine giren: lisans müdahale betikleri, `SafeBox_License_Service_Tamper` / `SafeBox_Patch_Keygen_Artifacts` YARA kuralları, üretici kimliği (vendor impersonation), HashMismatch, VirusTotal HackTool/Crack etiketleri, `hosts` ve güvenlik duvarı eklemeleri. **Aynı dosyada gerçek zararlı sinyali varsa** (başka bir yüksek önemli YARA kuralı, kritik dizi izi, başka bir kandırmaca) bu bulgular kırmızı kalıyor — zararlı "crack gibi görünerek" sarıya düşemez. Defender istisnası, yeni servis/sürücü ve şüpheli komut satırları her zaman kırmızı.
- **G5. Windows'un kendi servis/BITS değişiklikleri kırmızı bayrak veriyordu — ✅ DÜZELTİLDİ.** (Gerçek sandbox testinde, hiçbir örnek çalışmadan görüldü.)
  - *Sorun:* İzleyici servisleri "ad | başlatma türü | yol" satırı olarak karşılaştırdığı için Windows'un BITS servisini `Auto`'ya alması "1 yeni servis kuruldu" diye kırmızı çıkıyordu; ağ kapalıyken Windows'un `fs.microsoft.com`'dan yazı tipi indirme denemesi (BITS "Font Download") da kırmızıydı.
  - *Düzeltme:* Servisler adla karşılaştırılıyor: gerçekten yeni servisler `Services`, ayarı değişen mevcut servisler `ServicesChanged`. Çalıştırılan dosya değiştiyse **kırmızı** (servis ele geçirme), sadece başlatma türü değiştiyse not. Bütün adresleri Microsoft'a ait olan BITS görevleri kırmızı sayılmıyor; başka bir adres içeren her görev kırmızı kalıyor. Windows Sandbox'ın her çalıştırmada BITS'i `Auto`'ya alması (tam ad + tam Windows komut satırıyla eşleşerek) gürültü sayılıyor; çalıştırılan dosya değişirse yine kırmızı.
- **G6. Sandbox'ın yazdığı durum dosyası okunurken analiz düşebiliyordu — ✅ DÜZELTİLDİ.** (Gerçek sandbox testinde görüldü.)
  - *Sorun:* Gözlem döngüsü `output/status.txt`'yi korumasız okuyordu. İzleyici dosyayı tam o an yazıyorsa Windows dosyayı kilitliyor, ana bilgisayardaki okuma `PermissionError` veriyor ve **bütün analiz "hata" ile bitiyordu** (örnek çalışmış olsa bile). Uzun analizlerde olasılık artar.
  - *Düzeltme:* `_read_text_quiet`: kilitliyse boş döner, bir sonraki turda (4 sn sonra) tekrar okunur. Diğer okumalar (`live.json`, `timeline.log`) zaten korumalıydı.
- **G7. Hatayla biten analizde sandbox açık kalıyordu — ✅ DÜZELTİLDİ.** (G6'daki hatadan sonra gerçek sandbox'ta görüldü.)
  - *Sorun:* Sandbox'ı kapatan kod yalnızca her şey yolunda giderse çalışıyordu. Gözlem sırasında bir istisna olunca sandbox açık kalıyor, örnek izlenmeden çalışmaya devam ediyor ve sonraki her analiz "açık bir sandbox var" diye reddediliyordu.
  - *Düzeltme:* `stage_sandbox`'ın `finally` bloğu, ortam başlatılmış ama kapatılmamışsa (ve "açık bırak" seçilmemişse) Windows Sandbox'ı ya da VirtualBox VM'ini kapatıyor.
- **Test:** 189 test geçiyor (G1–G7 için 15 yeni test; iki eski test yeni tasarıma göre güncellendi: biri tam olarak G1'deki "hiçbir şey çalışmadı ama yeşil" durumunu bekliyordu).

## H. Sandbox'ı izleyebilmek ve crack bulgularının puanı (24 Kasım 2026)

Photoshop analizinden sonra iki şikâyet: analizin bittiği anlaşılmıyordu, ekran görüntülerinde hep boş masaüstü vardı (kurulum hiç başlamadığı için). İlerlemeyi görmek için sandbox'ı ekranda gösterme isteği vardı.

- **H1. Canlı sandbox ekranı — ✅ EKLENDİ.**
  - Sandbox içindeki izleyici her ~5 saniyede ekranı küçültüp (1024 px genişlik) `screenshots/live.png` olarak yazıyor. Panel analiz sürerken bu kareyi her 4 saniyede yeniliyor ("🔴 Canlı sandbox ekranı"). Kare de diğer görüntüler gibi PNG başlığıyla doğrulanıyor (sahte dosya karantinaya alınır) ve galeride görünmüyor.
  - Galeri için ekran görüntüsü aralığı sabit 30 sn yerine süreye göre ayarlanıyor (`max(30, süre/22)`), uzun analizlerde de galeri ~22 kareyi geçmiyor.
- **H2. "Sandbox penceresini öne getir" butonu — ✅ EKLENDİ.** Windows Sandbox zaten görünür bir pencere olarak açılıyor; arka planda kaldığı için görünmüyordu. Buton (`POST /api/sandbox/focus`) pencereyi küçültülmüşse geri açıp öne getiriyor. Windows izin vermezse görev çubuğunda yanıp söndüğünü söylüyor. Sandbox'ın içine tıklamak izlemeyi bozmaz, ama kurulumu yarıda kesmek sonucu eksik bırakır.
- **H3. Bitiş bandı — ✅ EKLENDİ.** Sonucun üstünde durum bandı: sürerken "⏳ Analiz sürüyor — <aşama>", bitince "✅ Analiz tamamlandı — X dk sürdü (başlangıç → bitiş)" ve sandbox'ta çalıştırılan dosya. Sandbox açılıp hiçbir şey çalıştırılmadıysa ayrıca kırmızı uyarı. Sekme başlığı da durumu gösteriyor.
- **H4. Crack puanları iki kez sayılıyordu — ✅ DÜZELTİLDİ.**
  - *Sorun:* Crack'ten tekrar paketlenmiş `Set-up.exe`'nin statik puanı (66) neredeyse tamamen crack bulgularından geliyordu: imzasız 20 + "Adobe Inc." üst verisi 30 + … Bunlar zaten turuncu listedeyken bir de "yüksek risk puanı" notu çıkıyordu.
  - *Düzeltme:* Gerçek zararlı sinyali olmayan dosyalarda, sonuç kuralları uygulanmadan önce crack bulgularının puanı (üretici kimliği, lisans betiği, crack YARA kuralları ve bunlarla birlikte "imzasız PE" puanı) çıkarılıyor (`pipeline._crack_points`). Gerçek zararlı sinyali varsa puan olduğu gibi kalıyor.
- **H5. Yamanın kendi `.log` dosyası "lisans müdahale betiği" sayılıyordu — ✅ DÜZELTİLDİ.** `Patch_Photoshop.exe_.log` gibi günlük ve metin dosyaları ne yapıldığını yazar ama kendileri hiçbir şey çalıştıramaz. Kurulum/lisans müdahale kontrolü artık sadece betik ve kurulum yapılandırma dosyalarına (`.cmd`, `.bat`, `.ps1`, `.iss`, `.inf`, `.ini` …) bakıyor.
- **Photoshop sonucunun yeni kurallarla durumu:** kırmızı → sarı. Turuncu listede 3 crack bulgusu var, "yüksek risk puanı" notu yok. Sandbox "çalıştırılmadı" diye işaretli, çünkü bu analiz G2 düzeltmesinden önceki kodla yapılmıştı; yeniden analiz gerekiyor.
- **H6. Windows'un duvar kâğıdı bağlantıları "bellekte zararlı iz" diye kırmızı çıkıyordu — ✅ DÜZELTİLDİ.** (Canlı ekran için yapılan gerçek sandbox testinde görüldü.)
  - *Sorun:* Zararsız bir `.bat` çalıştıran `cmd.exe`'nin belleğinde Windows 11'in Spotlight/Bing duvar kâğıdı bağlantıları (`bing.com`, `blogs.windows.com`) vardı; sandbox içindeki tarayıcı sadece `microsoft.com`'u zararsız sayıyor, sonuç kuralı da bellekte görülen **her** adresi kırmızı yapıyordu.
  - *Düzeltme:* `pipeline._split_memory_findings`: gerçek göstergeler (Telegram bot API, Discord webhook, mimikatz, AMSI atlatma …) ve kötüye kullanılan servislerdeki adresler kırmızı; Windows/Microsoft, Adobe ve yerel adresler atlanıyor; diğer adresler sadece not ("bellekte görüldü", bağlantı kurulduğu anlamına gelmez).
- **Gerçek sandbox doğrulaması:** 2 dakikalık testte panel 23 farklı canlı kare aldı (ilki 32. saniyede, kurulum penceresi görünüyordu); kare galeriye girmedi; sandbox kendiliğinden kapandı.
- **Test:** 193 test geçiyor (4 yeni test; `.log` dosyasının lisans betiği sayılmasını bekleyen eski test yeni karara göre güncellendi).

## I. Photoshop'un ikinci analizi: kurulum hiç başlamamıştı (24 Kasım 2026)

49 dakikalık analiz sarı çıktı ama sandbox'ta yalnızca ISO'daki `autoplay.exe` çalıştı: menüde "Install" butonu 30 dakika boyunca tıklanmayı bekledi, alt işlem yok, kurulum yok. Otomatik tıklayıcı "Install" kelimesini tanıyor, fakat menü özel çizilmiş olduğundan butonu Windows'a bildirmiyor.

- **I1. Asıl kurulum dosyası menüden önce seçiliyor — ✅ DÜZELTİLDİ.** Otomatik seçimde `set-up`/`setup`/`install` ile başlayan dosyalar `autoplay`/`autorun`/`start` menülerinden önce geliyor (sandbox içinde `Get-TargetRank` ve paneldeki liste aynı sırayı kullanıyor). Menü sadece başka kurulum dosyası yoksa seçilir.
- **I2. Hedefi elle seçmek, ISO içi dahil — ✅ DÜZELTİLDİ.** "Sandbox'ta tekrar çalıştır" penceresindeki dosya listesi, örnek sadece `.iso` içeriyorsa açılmış disk görüntüsünün içini gösteriyor (önceden boştu). Yollar sandbox'ın gördüğü klasöre göre (ör. `Adobe 2026\Set-up.exe`). İlk analizde de başlatma formundaki "Çalıştırılacak dosya" kutusuna aynı yol yazılabilir.
- **I3. Windows gürültüsü — ✅ DÜZELTİLDİ.** Windows Sandbox'ın kendi `IsolationSession` servisinin başlatma türü değişikliği (Auto → Manual) ve Windows 11'in kendi ipucu/bildirim görevleri (`\SoftLanding\<SID>\SoftLanding…Task`, eylemsiz) artık bulgu sayılmıyor. Çalıştırdığı dosya değişen servis ya da eylemi olan görev yine sayılıyor.
- **I4. "Kurulum başlamamış" uyarısı — ✅ EKLENDİ.** Çalıştırılan dosya bir kurulum/menü dosyasıysa ve tüm süre boyunca tek başına kaldıysa (alt işlem yok, otomatik tıklama yok, yeni program dosyası yok) sonuçta "Kurulum" incelenmemiş sayılıyor (`not_run`), not ekleniyor ve panelde turuncu bir uyarı bandı çıkıyor: asıl kurulum dosyasını seçmeyi ya da pencereyi açıp butona elle basmayı öneriyor. Sonuç bu durumda temiz görünmüyor.
- **I5. Sandbox penceresini ekranda gösterme seçeneği — ✅ EKLENDİ.** Başlatma formunda ve "tekrar çalıştır" penceresinde "Sandbox penceresini ekranda göster" kutusu: açıksa sandbox penceresi açılınca öne gelir, kurulumu kendiniz ilerletirsiniz; kapalıysa (varsayılan) pencere diğer pencerelerin arkasına alınır, analiz arka planda sürer ve paneldeki canlı ekrandan izlenir. Analiz sürerken "öne getir" ve "arka plana al" butonlarıyla geçiş yapılabiliyor. Windows Sandbox'ın kendi penceresi tarayıcı paneline gömülemez (ayrı bir Windows penceresi), bu yüzden geçiş pencereyi öne/arkaya almakla yapılıyor.
  - *Gerçek testte:* pencere arka plana alındı; pencere simge durumuna küçültülmüşken de sandbox içinden canlı kareler gelmeye devam etti. Yine de güvenli tarafta kalmak için arka plan modu pencereyi küçültmüyor, sadece arkaya alıyor.
- **I6. Statik analiz listesinde risk filtresi — ✅ EKLENDİ.** Liste başlığının yanında: Tümü, 🔴 Yüksek (65+), 50+, 🟠 Orta (35–64), 🟢 Düşük (0–34), 🛡️ VT'de işaretli. Her butonda o gruptaki dosya sayısı yazıyor; seçilen filtre analizler arasında geçişte korunuyor.
- **Gerçek sandbox doğrulaması:** `autoplay.bat` + `Adobe 2026\Set-up.bat` içeren klasörde `Set-up.bat` seçildi ve çalıştı (cmd.exe → PING.EXE), pencere arka plana alındı, kırmızı bulgu yok, uyarı yanlışlıkla çıkmadı.
- **Test:** 202 test geçiyor (9 yeni test).

## J. VirusTotal sandbox'ı bekletmiyor (25 Kasım 2026)

- **J1. VirusTotal ve sandbox aynı anda — ✅ DEĞİŞTİ.** Önceden adımlar sırayla çalışıyordu (statik → VirusTotal → sandbox). Ücretsiz VirusTotal API dakikada 4 istek kabul ettiği için 16 dosya sandbox'ı ~4 dakika bekletiyordu, oysa sandbox VirusTotal sonuçlarını kullanmıyor. Artık statik analiz biter bitmez VirusTotal arka planda başlıyor ve sandbox hemen açılıyor; rapor ikisi de bitince yazılıyor (sandbox önce biterse rapor adımında "VirusTotal sonuçları bekleniyor" yazar).
  - *Bellek:* VirusTotal sorguları küçük internet istekleri; ek bellek birkaç MB. Asıl yük her zamanki gibi sandbox'ın kendisi.
  - *Kota:* VirusTotal istemcisinin dakikada 4 istek sınırı tüm iş parçacıkları için ortak; sandbox'ın bıraktığı dosyalar için yaptığı sorgular da aynı sıraya giriyor, kota aşılmıyor.
  - *İptal:* İptal ikisini birden durduruyor (sandbox erken bitip o ana kadarki sonuçlar raporlanıyor, VirusTotal "iptal edildi" oluyor).
  - *Hata:* Sandbox hata verirse VirusTotal yine bitiriliyor, sonuçları kayboluyor.
  - Sonuç hesaplama artık analiz kilidi altında yapılıyor (iki iş parçacığı aynı anda hesaplayabiliyor). Panel bandı aynı anda çalışan adımları birlikte gösteriyor ("VirusTotal + Windows Sandbox").
  - "Sandbox'ı otomatik çalıştır" kapalıyken eski sıra korunuyor.
- **Test:** 205 test geçiyor (3 yeni test: sandbox VirusTotal'ı beklemeden başlar, iptal ikisini durdurur, sandbox hatasında VirusTotal sonuçları korunur).

## K. Çökme kayıtları ve isteğe bağlı ekran kartı (25 Kasım 2026)

Üçüncü Photoshop analizinde kurulum ve crack betiği tamamlandı, Photoshop açıldı ama resim açılınca iki kez kapandı. Sandbox'taki Windows hata kaydı: `Photoshop.exe` → `ntdll.dll`, kod `0xc0000409`, fast-fail **10** (Control Flow Guard ihlali), iki çökme de aynı adreste (`+0x127670`). Bu, ekran kartı eksikliğinden çok yamalanmış/kancalanmış kodla uyumlu bir tablo.

- **K1. Çökme kayıtları rapora giriyor — ✅ EKLENDİ.** İzleyici, analiz bitmeden Windows'un "Application Error" (1000) kayıtlarını ve aynı çökmenin "Windows Error Reporting" (1001, BEX/APPCRASH) kaydından fast-fail kodunu okuyor (`Get-CrashEvents`). Mesaj metni sandbox'ın diline göre değiştiği için olay özelliklerinden (Properties) okunuyor. Aynı program + modül + kod + adres tek satırda sayılıyor ("x2"). Sonuçta not olarak (kırmızı değil) anlaşılır bir açıklamayla çıkıyor; CFG ihlalinde, pakette crack bulgusu da varsa "yama bu sürümle uyumsuz olabilir" ekleniyor. Panelde "💥 Çöken programlar" kutusu, raporda ayrı bölüm.
  - Ana bilgisayarın gerçek kayıtlarıyla denendi (Unity, Explorer, Steam çökmeleri doğru okundu; Steam'in fast-fail 7 kodu WER kaydından birleştirildi).
- **K2. "Sandbox'a ekran kartı ver (GPU)" seçeneği — ✅ EKLENDİ.** Başlatma formunda ve "tekrar çalıştır" penceresinde, varsayılan kapalı. Açıkken `.wsb` dosyasında `VGpu=Enable`; GPU isteyen programlar (Photoshop vb.) çalışabilir ama ana bilgisayarın ekran kartı sürücüsü sandbox'a açıldığı için yalıtım daha zayıf. Panelde "🎮 Ekran kartı (vGPU) açık" uyarısı ve analiz günlüğünde not.
- **Sandbox'a metin/betik vermek:** pano paylaşımı bilerek kapalı. En rahat yol, analizin `output` klasörü: sandbox içinde `C:\Analysis\output` olarak görünüyor, oraya konan bir `.cmd` dosyası sandbox içinde çift tıklanarak çalıştırılabilir, yazdığı sonuç da ana bilgisayardan okunabilir.
- **Test:** 207 test geçiyor (2 yeni test).

## L. Sandbox penceresi kayboluyordu (25 Kasım 2026)

- **L1. "Ekranda göster" açıkken pencere kayboluyordu — ✅ DÜZELTİLDİ.** Sandbox çalışmaya devam ediyor ama ona ait hiçbir pencere kalmıyordu, bu yüzden "öne getir" de bir şey bulamıyordu. Pencere, sandbox açıldıktan 2 saniye sonra (masaüstü daha hazır değilken, uzak masaüstü görüntüleyicisi bağlanırken) yakalanıp öne getiriliyordu; araya giren bir commit (`e73aa36`) bunu `AttachThreadInput` ve geçici "her zaman üstte" ile yapıyordu.
  - *Düzeltme:* Öne getirme eski basit yönteme döndü (ALT tuşu + `SetForegroundWindow`). Pencereye ancak sandbox masaüstü hazır olunca (izleyici `status.txt`/`live.json` yazınca) dokunuluyor. "Ekranda göster" açıkken pencere izleniyor; sandbox çalışırken kaybolursa `wsb connect` ile yeni bir görüntüleyici açılıyor (en fazla 3 kez). "Öne getir" butonu da pencere yoksa önce yeniden bağlanıp pencerenin gelmesini 20 saniyeye kadar bekliyor. Arka plan modunda yeni pencere açılmıyor.
  - *Gerçek doğrulama:* Çalışan bir sandbox'a `wsb connect` ile elle yeni pencere bağlandı. Ardından 04:15'teki 34 dakikalık Photoshop analizinde pencere masaüstü hazır olunca öne geldi, hiç kaybolmadı; kurulum elle ilerletildi, Photoshop açılıp resim yüklendi, çökme olmadı (GPU kapalı).
- **Test:** 209 test geçiyor (2 yeni test).

## M. Bellek dökümü taraması, 1–10 puan ve MITRE ATT&CK (26 Kasım 2026)

Triage (tria.ge) karşılaştırmasındaki eksiklerden indirme gerektirmeyen ikisi (`futures.md` → Triage, madde 3 ve 4).

- **M1. Bellek dökümü + YARA — ✅ EKLENDİ.** Paketlenmiş/şifreli zararlıların gerçek kodu ve metinleri yalnızca bellekte açılır. İzleyici, gözlem bitince örnek ağacındaki süreçlerin **özel (private) ve çalıştırılabilir** bellek bölgelerini döküyor (`DumpProcess`; süreç başına 64 MB, toplam 192 MB, en fazla 6 süreç; eşlenmiş veri dosyaları atlanıyor). Dökümler ana bilgisayarın antivirüsü silmesin diye XOR ile kodlanıyor (`output/memdumps/*.xbin`), ana bilgisayarda yalnızca bellekte çözülüp 16 MB'lık parçalar hâlinde (parça sınırında kaçmasın diye 64 KB örtüşme) mevcut YARA kurallarıyla taranıyor ve **sonra siliniyor**.
  - *Sonuç kuralı (bilerek temkinli):* bellek, dosyadan çok daha gürültülü. Kırmızı yalnızca **kritik** kurallar (kimlik/cüzdan hırsızı, fidye yazılımı gölge kopya silme, ters kabuk, LSASS dökümü, WMI kalıcılığı) ve süreç tarayıcı/gömülü tarayıcı motoru değilse (Edge/Chrome/CEF/WebView2 kendi profil dosyalarının adlarını zaten bellekte tutar). Diğer eşleşmeler not, crack kuralları turuncu.
  - Sınır: yalnızca gözlem bittiğinde hâlâ çalışan süreçler dökülebiliyor; erken kapanan bir yükleyici yakalanmaz.
  - *Betik motorları ölçüldü:* temiz, boşta bekleyen bir `powershell.exe` kendi belleğinde 6 kuralımıza uyuyor (kritik "LSASS dökümü" dahil, ayrıca AMSI atlatma, gizli indirme, Defender istisnası, .NET yükleyici); `cmd.exe` hiçbirine uymuyor. Bu yüzden betik motorlarındaki (powershell, pwsh, cmd, wscript, cscript, mshta, python, node, java) bellek eşleşmeleri ve eski bellek gösterge taraması (`AmsiScanBuffer`, `NtUnmapViewOfSection`…) not olarak gösteriliyor; betiğin kendisi statik analiz ve komut satırı kontrolleriyle değerlendiriliyor.
  - *Gerçek sandbox testi:* belleğinde hırsız benzeri metinler tutan zararsız bir betik: dökümler yazıldı (cmd.exe 13,6 MB, powershell.exe 64 MB), ana bilgisayarda tarandı, eşleşmeler bulundu, dökümler silindi (klasör kalmadı).
- **M2. 1–10 puan — ✅ EKLENDİ.** Kırmızı/sarı/yeşil seviyesinin yanında Triage benzeri puan: **10** bilinen zararlı (MalwareBazaar/ThreatFox/CIRCL, VirusTotal aile tespiti ya da bellek dökümünde kırmızı kural), **8–9** kırmızı bulgular (3+ ise 9), **5–6** crack/lisans müdahalesi, **3–4** sadece notlar, **1** bulgu yok. Bir kontrol yapılmadıysa "eksik analiz" işareti. Photoshop paketi: **6/10 — Şüpheli (crack / lisans müdahalesi)**.
- **M3. MITRE ATT&CK eşlemesi — ✅ EKLENDİ.** Bulgular 25 tekniğe eşleniyor (ör. Defender değişikliği → T1562.001, yeni servis → T1543.003, zamanlanmış görev → T1053.005, sahte üretici → T1036, lisans servisi durdurma → T1489, tarayıcı kimlik bilgisi → T1555.003). Panelde bulgu kutusunun altında attack.mitre.org bağlantılı etiketler (kırmızı/turuncu/gri, üzerine gelince kanıt), raporda ayrı bölüm.
- **M4. Artık sandbox'ı olmayan pencere süreci yeni analizi engelliyordu — ✅ DÜZELTİLDİ.** Bir analizden kalan, penceresiz `WindowsSandboxRemoteSession.exe` "açık sandbox var" sayılıyordu; `wsb list` boşken ve sandbox sanal makinesi (`vmmemWindowsSandbox`) yokken tek başına bir görüntüleyici süreci artık çalışan sandbox sayılmıyor (`wsb` yoksa eski temkinli davranış korunuyor).
- **Test:** 220 test geçiyor.

## N. Zararlı ailesi / ayar çıkarma ve HTTPS çözme (26 Kasım 2026)

Triage karşılaştırmasındaki 1. ve 2. madde. İkisi de ayrıca indirilen araçlara dayanıyor; araçlar **depoya girmiyor**, `%LOCALAPPDATA%\SafeBox\` altında duruyor ve yoksa ilgili adım sessizce atlanıyor (panelde rozet: "Aile / ayar ayıklayıcı yok").

| Araç | Kaynak | Boyut | Lisans | Yer |
|---|---|---|---|---|
| Python 3.13.13 (yalnızca bu kullanıcı, PATH'e eklenmedi) | python.org, PSF imzalı | 29,1 MB | PSF | `SafeBox\python313` |
| CAPE-parsers 0.1.74 + kütüphaneler (ayrı sanal ortam) | PyPI | ~28 MB indirme, 108 MB kurulu | MIT | `SafeBox\extractor-venv` |
| CAPE aile YARA kuralları (114 dosya) | github.com/kevoreilly/CAPEv2 `data/yara/CAPE` | 113 KB | GPLv3 | `SafeBox\cape-rules` |
| mitmproxy 12.3.1 `mitmdump.exe` | downloads.mitmproxy.org (zip 88,4 MB, imzasız resmi derleme) | 28,7 MB | MIT | `SafeBox\mitmproxy` |

- CAPE-parsers Python ≥3.12 istiyor, panel 3.11'de; Python 3.12'nin son Windows kurulumu (3.12.10) sonraki güvenlik düzeltmelerini içermediği için bakımı süren 3.13 seçildi. Panelin Python'una dokunulmadı.
- CAPE kuralları GPLv3 olduğu için herkese açık depoya konmadı.
- `mitmdump.exe` imzasız (mitmproxy derlemelerini imzalamıyor). Yalnızca sandbox içinde çalışıyor; dosyanın SHA-256'sı koda sabitlendi (`MITM_SHA256`), değişirse sandbox'a bağlanmıyor.

- **N1. Zararlı ailesi tespiti ve ayar (C2) çıkarma — ✅ EKLENDİ.** `config_extractor.py` ayrı ortamda ve ayrı süreçte çalışıyor (şüpheli dosyaları üçüncü taraf ayrıştırıcılarla okuduğu için): CAPE aile kuralları dosyada aileyi tanıyor, o ailenin ayrıştırıcısı (66 aile: Lumma, Vidar, RedLine, Stealc, AgentTesla, AsyncRAT, Remcos, XWorm, DCRat…) ayarı çıkarıyor. Statik aşamada en riskli 40 çalıştırılabilir dosyaya (≤64 MB), sandbox'tan sonra bellek dökümlerine (silinmeden önce; şifreli döküm yalnızca bellekte çözülüyor) uygulanıyor.
  - Sonuç: aile eşleşmesi **kırmızı** ve puan **10** ("Zararlı ailesi tespit edildi: Lumma — 'Set-up.exe' (statik). Ayardan çıkan adresler (C2): …"); ayardaki adresler IOC dışa aktarımına "zararlı ailesi C2" olarak giriyor. Obfuscar (.NET karıştırıcı) ve Pafish (anti-VM test aracı) gibi araç kuralları sadece not. Panelde "💀 Zararlı ailesi" kutusu, raporda ayrı bölüm.
  - Doğrulama: yalnızca bir aile kuralının aradığı metinleri içeren sentetik dosya hem diskte hem XOR'lu bellek dökümü olarak AgentTesla olarak tanındı (statik risk puanı 0/100 iken); Windows'un notepad'i ve Photoshop paketinin çalıştırılabilirleri temiz çıktı (0,7 sn). **Gerçek bir zararlıdan ayar çıkarılması denenmedi** (örnek yok); ayrıştırıcıların kendisi CAPE projesinin.
- **N2. HTTPS trafiğini çözme — ✅ EKLENDİ (isteğe bağlı, varsayılan kapalı).** "HTTPS trafiğini çöz (mitmproxy)" seçilirse sandbox içinde `mitmdump --mode local` tüm programların trafiğini (proxy ayarı gerektirmeden) yakalıyor, kendi kök sertifikası sandbox'ta güvenilir olarak ekleniyor, `https_logger.py` eklentisi her istek için yöntem, tam adres, durum, boyut ve **gönderilen** verinin ilk 1 KB'ını `output/https_log.jsonl`'a yazıyor (yanıt gövdeleri tutulmuyor; en fazla 5000 satır, ana bilgisayarda 20 MB'a kadar okunuyor, güvenilmeyen veri olarak).
  - Sonuç: kötüye kullanılan servislere (Telegram bot API, Discord webhook, Pastebin…) HTTPS istekleri kırmızı; Microsoft/Adobe dışı adreslere veri gönderen POST/PUT istekleri not; sertifika sabitleyen (çözülemeyen) adresler not; çözme çalışmadıysa not. mitmproxy'nin kendi dinleyici portu bulgu sayılmıyor.
  - Uyarı: kendi sertifikasını bekleyen programlar (bazı kurulumlar, güncelleyiciler) bu modda bağlanamayabilir, bu da davranışı değiştirebilir; bu yüzden varsayılan kapalı ve yalnızca internet açıkken çalışıyor.
  - *Gerçek sandbox testi:* `example.com` / `example.org`'a HTTPS isteği yapan zararsız bir betik: CA güvenilir eklendi, 44 istek çözüldü, test adresleri tam yollarıyla ve programın kimliğiyle (curl, PowerShell) göründü; sertifika sabitleyen bir Windows adresi (`arc.msn.com`) "çözülemedi" olarak işaretlendi.
  - *mitmproxy'nin kendi izleri bulgu sayılmıyor (sadece HTTPS çözme açıkken):* yerel yakalama için yüklediği WinDivert paket sürücüsü (yalnızca kendi açılmış paket klasöründen, `%TEMP%\_MEI…\mitmproxy_windows\WinDivert64.sys`) ve kendini açtığı `_MEI…` klasöründeki dosyalar. Başka yerden yüklenen WinDivert ya da başka `_MEI` klasörleri (PyInstaller ile paketlenmiş zararlılar da böyle açılır) bulgu olmaya devam ediyor. Test analizi bu düzeltmelerden önce yanlışlıkla kırmızıydı ("1 yeni sürücü"), sonra 3/10.
- **Test:** 226 test geçiyor.
