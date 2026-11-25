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
