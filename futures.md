# Gelecek fikirler

Henüz yapılmamış, üzerinde konuşulmuş geliştirmeler. Son güncelleme: 28 Kasım 2026, commit `9959f4d`. Proje bu noktada bir süre rafa kalkıyor; geri dönüldüğünde önce "Doğrulanmamış olanlar" bölümüne bakılmalı.

## Yapılanlar (Kasım 2026)

Bu belgedeki eski fikirlerden yapılanlar, ayrıntıları commit mesajlarında:

| Fikir | Commit |
|---|---|
| Bellek dökümünde YARA, 1–10 puan, MITRE ATT&CK etiketleri | `8c8a456` |
| Zararlı ailesi / C2 ayarı çıkarma (CAPE ayrıştırıcıları), HTTPS çözme (mitmproxy) | `f4eb3e8`, `3cfe9f0` |
| Bağlantı (URL) analizi: Edge sandbox içinde açar, indirilenler çalıştırılmadan incelenir | `b18a0bf` |
| Örneğin bıraktığı dosyaların ve çalıştırdığı PowerShell'in (4104) incelenmesi | `93ad499` |
| Panel yeniden tasarımı: adım adım yeni analiz, sekmeli sonuçlar, sayfalama | `92a6c90` |
| FLOSS / capa, birleşik kurallar, süreç ağacı | `9959f4d` |

## Doğrulanmamış olanlar (önce bunlar)

Kod ve testler var, ama gerçek koşulda denenmedi:

1. **Yeni panel canlı sandbox çalıştırmasında denenmedi.** Canlı ekran sekmesi, bağlantı analizini başlatma ve sürükle-bırak yükleme yeni arayüzde hiç kullanılmadı.
2. **Birleşik kurallar gerçek bir zararlıda hiç tetiklenmedi.** Yedi kural (bilgi çalma zinciri, indirip çalıştırma, bıraktığını otomatik başlatma, .NET aracına enjeksiyon, sandbox'ı fark etme, gizli adrese bağlanma, fidye deseni) yalnızca testteki örnek verilerle doğrulandı. Yanlış alarm denemesi tek bir gerçek analizle (Photoshop.2026) yapıldı; hiçbiri tetiklenmedi. Aşağıdaki "Kıyaslama yöntemi" bunun için.
3. **CAPE ayar çıkarma gerçek zararlıda denenmedi.** Sentetik bir dosyada ve meşru programlarda (eşleşme yok) denendi.
4. **FLOSS'un gizli metinden C2 bulması** yalnızca testlerle doğrulandı; gerçek bir dosyada FLOSS yalnızca notepad'in tek yığın metnini buldu.

## Triage (tria.ge) ile karşılaştırmadan kalanlar

[Triage](https://tria.ge/) (Recorded Future Sandbox) eksiklerimizi görmek için ölçüt olarak kullanıldı. İlk dört büyük fark (aile / ayar çıkarma, HTTPS çözme, bellek dökümü taraması, puan + ATT&CK) yapıldı. Kalanlar, önem sırasıyla:

1. **Triage'ı istihbarat kaynağı olarak eklemek.** MalwareBazaar / Hybrid Analysis gibi hash ile API sorgusu (ücretsiz kayıt + API anahtarı, `https://tria.ge/api/v0/`, resmi Python istemcisi `hatching/triage`). Başkası taratmışsa puan, aile ve C2 ayarı yükleme yapmadan rapora gelir. Kolay (mevcut `intel_client.py`'nin bir benzeri), getirisi orta: VirusTotal / MalwareBazaar / Hybrid Analysis zaten var.
2. **Bağlantı analizinde indirilen dosyayı çalıştırma seçeneği.** Şu an indirilen dosya çalıştırılmadan inceleniyor; davranışı için ikinci bir analiz gerekiyor. Aynı sandbox'ta, varsayılanı kapalı bir seçenekle indirilen dosyayı çalıştırıp izlemek. Dikkat: Edge'in kendi izlerini örneğinkilerden ayırma kuralları (`_edge_noise`) bu modda da geçerli olmalı.
3. **JA3 / JA4 (TLS istemci parmak izi).** tshark ile ağ kaydından kolayca çıkar, ama tek başına anlamı yok: bilinen zararlı parmak izleri listesiyle karşılaştırılması gerekir. Ayrıca **HTTPS çözme açıkken dışarı çıkan el sıkışması mitmproxy'nin kendisine ait olur**, örneğin değil; yani yalnızca HTTPS çözme kapalıyken anlamlı. En düşük öncelik.
4. **Linux, macOS, Android konukları:** kapsam Windows olduğu için eksik sayılmıyor.

### ⚠️ Triage'ı kullanırken dikkat

- Ücretsiz sürümde **yüklenen her dosya herkese açık ve silinemiyor**; gizli analiz için ücretli kurumsal sürüm gerekiyor. Kişisel/iş dosyası ya da başkasının telifli yazılımı yüklenmez.
- Güvenli kullanım **hash ile aramak**: `https://tria.ge/s?q=<sha256>`. Panelde her dosyanın altındaki "Triage ↗" bağlantısı bunu yapıyor. (Otomatik istekler zaman aşımı / 502 aldı; tarayıcıdan bakılmalı.)

### Bizde olup Triage'ın ücretsiz sürümünde olmayanlar (bilinçli tercihler)

Yerel ve gizli çalışma; crack'e özel turuncu sınıf ("crack'te beklenen davranış" ayrımı); yem dosyalar (honeyfile); ev ağı engeli; statik + VirusTotal + diğer istihbarat + davranış aynı raporda.

### Kıyaslama yöntemi

Herkese açık ve Triage'da analizi zaten bulunan **bilinen zararlı örnekleri** (ör. MalwareBazaar'dan, aile etiketli) bizim sandbox'ta çalıştırıp iki raporu yan yana koymak: "onlar buldu, biz bulamadık" listesi hiçbir şey yüklemeden çıkar. Gerçek zararlı indirildiği için yalnızca internet kapalıyken / ev ağı engeli açıkken, şifreli arşivden doğrudan sandbox'a verilerek yapılmalı. Birleşik kuralların ve CAPE ayar çıkarmanın gerçekte çalışıp çalışmadığı da böyle görülür.

## FLOSS / capa'nın sınırları

Ölçümler (iki araç aynı anda): notepad.exe 0,35 MB capa 34 sn / FLOSS 52 sn; Magnify.exe 1,3 MB capa 6 dk / FLOSS 10 dakikada bitmedi; 3,6 MB ve 7,6 MB'lık programlar 5 ve 19 dakikada bitmedi. Bu yüzden capa 2 MB, FLOSS 1 MB ile sınırlı; büyük kurulum dosyaları "incelenmedi" diye listeleniyor.

- **Hızlandırma:** İkisi de aynı dosya için ayrı ayrı vivisect çalışma alanı kuruyor. capa'nın `--backend` seçenekleri (Binary Ninja / IDA / Ghidra) daha hızlı ama ek kurulum ister. .NET dosyalarında capa ayrı ve hızlı bir arka uç kullanıyor; .NET için sınır yükseltilebilir (FLOSS .NET'i desteklemiyor zaten). Ölçülmedi.
- **Sunucu çökerse yetim süreç:** Süre dolunca süreç ağacının tamamı kapatılıyor (`taskkill /T`). Ama SafeBox sunucusu analiz sırasında kapanırsa çalışan capa / FLOSS süreçleri kalabilir. Windows Job Object ile (üst süreç ölünce çocukları da ölsün) çözülebilir.
- **Statik ↔ dinamik adres karşılaştırması** kısmen yapıldı: FLOSS'un gizli adreslerinden biri sandbox'ta bağlanılırsa birleşik kural kırmızı veriyor. Eksik olan: kodda geçen ama hiç bağlanılmayan adresleri ayrı bir "uyuyan / koşullu bağlantılar" bölümünde göstermek; kodda olmayıp çalışırken ortaya çıkan adresleri ayrıca işaretlemek.

## Statik analiz: kalan fikir

- **Crack yaması farkı:** Yamalanmış dosyayı (ör. bir Adobe DLL'i) orijinaliyle karşılaştırıp hangi baytların ve fonksiyonların değiştiğini göstermek. Crack'in yalnızca lisans kontrolünü mü kapattığını, yoksa koda başka bir şey mi eklediğini en net bu gösterir. Orijinal dosya: aynı sürümün resmi kurulumundan ya da hash ile VirusTotal/CIRCL'den.

## Küçük iyileştirmeler

- **Yanlış alarmlar (Photoshop analizlerinden):**
  - Yem dosyayı örnekle ilgisi olmayan, kullanıcının açtığı bir programın okuması (sandbox içinde Edge'i açınca Chrome'un "Local State" dosyasını ve masaüstündeki `wallet_keys.txt`'yi okuması) kırmızı değil not olsun. (Bağlantı analizinde Edge için yapıldı; dosya analizinde kullanıcının elle açtığı programlar için değil.)
  - Edge'in ilk açılışta kendi kısayollarını güncellemesi (`Quick Launch\Microsoft Edge.lnk`) "çalıştırılabilir dosya değiştirildi" sayılmasın.
- **Bilinen zararsız adresler listesine eklenecekler:**
  - `contentcredentials.org`, `verify.contentauthenticity.org` (Adobe içerik kimliği)
  - `crt.usertrust.com` (sertifika kontrolü)
  - `*.ingest.sentry.io` (uygulama hata raporlama)
  - `Passport.NET` (Microsoft'un eski giriş adresi, Windows bileşenlerinin belleğinde görülüyor; yeni panelde Photoshop analizinin bellek bölümünde hâlâ görünüyor)
- **Disk kullanımı:** Sandbox kapandıktan sonra açılmış disk görüntüsünü (`image_root`, Photoshop'ta ~5,7 GB) silme seçeneği. ISO'daki dosya listesi analiz kaydında saklanır ki "tekrar çalıştır" listesi boş kalmasın; "süre bitince açık bırak" seçiliyse silinmez. Şimdilik kullanıcı elle siliyor.
- **Özel çizilmiş butonlar:** Adobe kurulumu gibi web tabanlı pencerelerde otomatik tıklayıcı butonları göremiyor (Windows'a buton olarak bildirilmiyorlar). Ekran görüntüsünde butonu görsel olarak bulup tıklamak (OCR / görüntü eşleme) ile çözülebilir.
- **Statik analiz meta bilgileri:** Yalnızca statik analiz yapılan bir işte iş başlığındaki "Windows Sandbox · 10 dk izleme · internet açık" etiketleri sandbox çalışmadığı hâlde görünüyor; sandbox bekliyorsa "sandbox bekliyor" gibi tek bir etiket yeterli.
- **Profil README'si:** FLOSS / capa ve birleşik kurallar `erkinavcii` profil README'sindeki SafeBox bölümüne henüz eklenmedi.
