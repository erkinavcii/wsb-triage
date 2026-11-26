# Gelecek fikirler

Henüz yapılmamış, üzerinde konuşulmuş geliştirmeler. Yapıldıkça `fable.md`'ye taşınır.

## Statik analiz / tersine mühendislik (koddan "nereye gönderiyor")

Şu anki analiz ağırlıklı olarak **dinamik**: dosya sandbox'ta çalıştırılıp ne yaptığı izleniyor. Koda bakan **statik** analiz bunu tamamlar: dinamik analizin 30 dakikada göremediği "uyuyan" davranışları (belli bir tarihte, ülkede ya da sandbox dışında devreye giren kod) ancak kod gösterebilir.

Bugün olanlar: dosyalardaki düz URL/IP izlerinin çıkarılması (`interesting_urls`, `interesting_ips`), YARA kuralları, PE import birleşimleri, betiklerde gizli komut çözme, çalışan süreçlerin belleğinde adres taraması.

Sınırlar: adres şifreli ayar bloğunda, çalışırken çözülen metinlerde, her gün yeniden üretilen alan adlarında (DGA) ya da sonradan bir yerden (Pastebin, Telegram) çekiliyorsa düz okuma bulamaz; paketlenmiş (packer) dosyalarda önce açmak gerekir.

### Eklenebilecekler

1. **FLOSS (Mandiant, ücretsiz CLI):** Normal metin çıkarmanın göremediği, çalışırken kod içinde oluşturulan (stack strings) ya da çözülen metinleri otomatik çıkarır. Gizlenmiş URL/IP/alan adı bulmak için.
2. **capa (Mandiant, ücretsiz CLI):** Kodun yeteneklerini, hangi fonksiyonda olduklarıyla listeler: "HTTP isteği gönderir", "AES ile şifreler", "tarayıcı şifrelerini okur", "sanal makine/sandbox tespit eder". Raporda "kodun yapabildikleri" bölümü.
3. **Statik ↔ dinamik adres karşılaştırması:** Kodda geçen ama sandbox'ta çalışırken hiç bağlanılmayan adresler ayrı bir rapor bölümünde ("uyuyan/koşullu bağlantılar"). Kodda olmayıp çalışırken ortaya çıkan adresler de ayrıca işaretlenir (çalışırken çözülen ya da indirilen ayar).
4. **Crack yaması farkı:** Yamalanmış dosyayı (ör. bir Adobe DLL'i) orijinaliyle karşılaştırıp hangi baytların ve fonksiyonların değiştiğini göstermek. Crack'in yalnızca lisans kontrolünü mü kapattığını, yoksa koda başka bir şey mi eklediğini en net bu gösterir. Orijinal dosya: aynı sürümün resmi kurulumundan ya da hash ile VirusTotal/CIRCL'den.

### Uygulama notları

- FLOSS ve capa büyük meşru programlarda (ör. `Photoshop.exe`) çok yavaş ve gürültülü olur, içinde üreticinin yüzlerce gerçek adresi çıkar. Önce küçük ve şüpheli dosyalarla sınırla: imzasız/imzası bozuk PE'ler, crack olarak işaretlenen dosyalar, tekrar paketlenmiş kurulum dosyaları, statik risk puanı yüksek olanlar. Dosya başına süre ve boyut sınırı.
- Araçlar yoksa adım atlanır ve "yapılmadı" olarak görünür (VirusTotal anahtarı olmadığında olduğu gibi).
- Çıkan adresler mevcut alan adı sınıflandırmasından (`domain_class`) geçer; Microsoft/Adobe gürültüsü ayrılır, kötüye kullanılan servisler (Telegram bot API, Discord webhook, Pastebin) kırmızı.

## Küçük iyileştirmeler

- **Yanlış alarmlar (Photoshop analizlerinden):**
  - Yem dosyayı örnekle ilgisi olmayan, kullanıcının açtığı bir programın okuması (sandbox içinde Edge'i açınca Chrome'un "Local State" dosyasını ve masaüstündeki `wallet_keys.txt`'yi okuması) kırmızı değil not olsun.
  - Edge'in ilk açılışta kendi kısayollarını güncellemesi (`Quick Launch\Microsoft Edge.lnk`) "çalıştırılabilir dosya değiştirildi" sayılmasın.
- **Bilinen zararsız adresler listesine eklenecekler:**
  - `contentcredentials.org`, `verify.contentauthenticity.org` (Adobe içerik kimliği)
  - `crt.usertrust.com` (sertifika kontrolü)
  - `*.ingest.sentry.io` (uygulama hata raporlama)
  - `Passport.NET` (Microsoft'un eski giriş adresi, Windows bileşenlerinin belleğinde görülüyor)
- **Disk kullanımı:** Sandbox kapandıktan sonra açılmış disk görüntüsünü (`image_root`, Photoshop'ta ~5,7 GB) silme seçeneği. ISO'daki dosya listesi analiz kaydında saklanır ki "tekrar çalıştır" listesi boş kalmasın; "süre bitince açık bırak" seçiliyse silinmez. Şimdilik kullanıcı elle siliyor.
- **Özel çizilmiş butonlar:** Adobe kurulumu gibi web tabanlı pencerelerde otomatik tıklayıcı butonları göremiyor (Windows'a buton olarak bildirilmiyorlar). Ekran görüntüsünde butonu görsel olarak bulup tıklamak (OCR / görüntü eşleme) ile çözülebilir.

## Triage (tria.ge) ile karşılaştırma

[Triage](https://tria.ge/) (Recorded Future Sandbox) eksiklerimizi görmek için iyi bir ölçüt. Kendi dokümanlarından (ana sayfa, docs, analysis, FAQ, scoring, live monitor sayfaları) okunanlara göre:

### ⚠️ Kullanırken dikkat

- Ücretsiz sürümde **yüklenen her dosya herkese açık ve silinemiyor**; gizli analiz için ücretli kurumsal sürüm gerekiyor. Kişisel/iş dosyası ya da başkasının telifli yazılımı yüklenmez.
- Güvenli kullanım **hash ile aramak**: `https://tria.ge/s?q=<sha256>`. Panelde her dosyanın altındaki "Triage ↗" bağlantısı bunu yapıyor. (Otomatik istekler zaman aşımı / 502 aldı; tarayıcıdan bakılmalı.)

### Triage'da olup bizde eksik olanlar

1. **Zararlı ailesi tespiti ve ayar (config) çıkarma — en büyük fark.** Bilinen bir aileyi tanıyınca içindeki ayarı çıkarıyor: komuta sunucusu (C2) adresleri, anahtarlar, botnet/kampanya kimlikleri. Statik ayar çıkarılabiliyorsa davranış analizine gerek kalmadan puan veriyor. Açık kaynak karşılıklar: CAPE sandbox ayar çıkarıcıları, MACO, DC3-MWCP. (Yukarıdaki "koddan nereye gönderiyor" bölümünün hazır cevabı.)
2. **HTTPS trafiğini çözme.** Ağ kaydında şifresi çözülmüş HTTPS de var. Biz sadece alan adını görüyoruz, içeriği göremiyoruz. Sandbox'a kendi sertifikamızı kurup araya proxy (ör. mitmproxy) koyarak yapılabilir; sertifika sabitleyen programlarda çalışmaz.
3. **Bellek dökümü üzerinde tarama.** Süreç belleğini döküp tarıyor; paketlenmiş zararlının bellekte açılmış gerçek kodu orada yakalanır. Biz bellekte sadece adres ve birkaç gösterge arıyoruz; YARA kurallarımız bellek dökümünde de çalıştırılabilir (ayar çıkarma da dökümden yapılabilir).
4. **1–10 puan ve TTP / MITRE ATT&CK eşlemesi.** Puan tetiklenen imzalardan çıkıyor (10 bilinen zararlı aile, 8–9 büyük olasılıkla zararlı, 5–7 şüpheli, 2–4 büyük olasılıkla zararsız, 1 zararlı davranış yok). Bulgularımızı ATT&CK teknik kodlarıyla etiketlemek raporu başka araçlarla karşılaştırılabilir yapar.
5. **Triage'ı istihbarat kaynağı olarak eklemek.** MalwareBazaar / Hybrid Analysis gibi hash ile API sorgusu (ücretsiz kayıt + API anahtarı, `https://tria.ge/api/v0/`, resmi Python istemcisi `hatching/triage`). Başkası taratmışsa puan ve aile yükleme yapmadan rapora gelir.
6. **Linux, macOS, Android konukları** — bizim kapsamımız Windows olduğu için eksik sayılmıyor.

### Bizde olup Triage'ın ücretsiz sürümünde olmayanlar (bilinçli tercihler)

Yerel ve gizli çalışma; crack'e özel turuncu sınıf ("crack'te beklenen davranış" ayrımı); yem dosyalar (honeyfile); ev ağı engeli; statik + VirusTotal + diğer istihbarat + davranış aynı raporda.

### Kıyaslama yöntemi

Herkese açık ve Triage'da analizi zaten bulunan **bilinen zararlı örnekleri** (ör. MalwareBazaar'dan, aile etiketli) bizim sandbox'ta çalıştırıp iki raporu yan yana koymak: "onlar buldu, biz bulamadık" listesi hiçbir şey yüklemeden çıkar. Gerçek zararlı indirildiği için yalnızca internet kapalıyken / ev ağı engeli açıkken, şifreli arşivden doğrudan sandbox'a verilerek yapılmalı.
