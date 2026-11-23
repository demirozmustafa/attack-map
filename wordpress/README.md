# Threat Origin Map — WordPress eklentisi (CloudPanel)

Docker sürümünün WordPress eklentisi hâli. Firewall / IDS cihazınızın engellediği bağlantıları ve IDS alarmlarını alır, saldırganın ülkesini bulur ve sitenizdeki bir sayfada canlı dünya haritasında gösterir. Ayarların hepsi WordPress yönetim panelinden yapılır.

```
pfSense / OPNsense / FortiGate / Suricata
        │ syslog (UDP 5514)
        ▼
 toplayıcı servisi (eklentinin içinde, systemd)  ──┐
                                                  ├─► WordPress veritabanı ─► [attack_map] sayfası
 HTTPS /wp-json/tom/v1/ingest (isteğe bağlı) ─────┘        (GeoLite2 ile IP → konum)
```

**Neden ayrı bir servis var:** PHP-FPM bir isteğe yanıt verir ve kapanır. Sürekli açık kalıp UDP syslog dinleyemez. Bu yüzden eklentinin içinde küçük bir PHP toplayıcısı vardır. CloudPanel sunucunuzda systemd servisi olarak çalışır, logları toplar ve WordPress veritabanına yazar. Kurulum komutu, yönetim panelinde sunucunuza göre doldurulmuş olarak hazır gelir.

## Kurulum

0. **Zip dosyasını hazırlayın:** WordPress, eklentiyi `threat-origin-map` klasörünü içeren bir zip olarak ister. GitHub'ın "Download ZIP" düğmesi bütün depoyu indirir, o dosya doğrudan yüklenmez. Depoyu indirdiğiniz yerde:

   ```bash
   cd wordpress && zip -r threat-origin-map.zip threat-origin-map
   ```

   Windows'ta `wordpress\threat-origin-map` klasörüne sağ tıklayıp **Sıkıştırılmış klasöre gönder** de aynı işi yapar.

1. **Eklentiyi yükleyin:** WordPress yönetim paneli → **Eklentiler → Yeni Ekle → Eklenti Yükle** → `threat-origin-map.zip` → **Şimdi Kur** → **Etkinleştir**.
2. Sol menüde **Saldırı Haritası** çıkar. Oradaki sırayla ilerleyin:
   1. **GeoIP:** maxmind.com'da ücretsiz GeoLite2 hesabı açın. Account ID ve License Key'i girin, **Kaydet**'e ve ardından **Şimdi indir**'e basın.
   2. **Cihaz bağlama → 1. adım:** Sunucuya SSH ile bağlanın, sayfadaki kutuyu kopyalayıp yapıştırın. Bu adım toplayıcı servisini kurar ve başlatır. Birkaç saniye sonra Durum bölümünde *Toplayıcı servisi: Çalışıyor* görünür.
   3. **Cihaz bağlama → 2. adım:** CloudPanel → Admin Area → Security → Firewall'da UDP 5514'ü yalnızca firewall cihazınızın IP'sine açın. Panel UDP seçeneği sunmuyorsa sayfadaki `ufw` komutunu kullanın. Bulut sağlayıcınızın kendi güvenlik duvarı varsa orada da açın.
   4. **Cihaz bağlama → 3. adım:** pfSense / OPNsense / FortiGate / Suricata sekmesindeki adımları cihazınızda uygulayın. Sunucu adresi ve port hazır yazılıdır.
3. **Haritayı sayfaya ekleyin:** Yeni bir sayfa açın, **Kısa kod** bloğu ekleyin ve şunu yazın:

   ```
   [attack_map align="full"]
   ```

   | Seçenek | Anlamı |
   |---|---|
   | `align="full"` | Tam ekran genişliği. Blok temalarda önerilir; dar içerik alanında harita tek sütuna düşer. |
   | `align="wide"` | Geniş içerik alanı |
   | `height="800"` | Masaüstünde yükseklik (piksel) |
   | `title="..."` | Başlık (varsayılan Ayarlar'daki başlık) |

   Haritada **Full screen** düğmesi vardır. Duvar ekranı için kullanışlıdır.

Log gelmeden denemek için Ayarlar → Görünüm'de **Demo verisi**'ni açın ya da Durum'daki **Test saldırısı gönder**'e basın.

## Yönetim sayfası

| Bölüm | Ne yapılır |
|---|---|
| **Durum** | Toplayıcı servisi çalışıyor mu, GeoIP hazır mı, alınan/işlenen satırlar. Log gönderen cihazlar listelenir. İzinli olmayan bir cihaz **İzin ver** ile tek tıkla eklenir. |
| **Cihaz bağlama** | systemd kurulum komutu, port açma, cihaz başına adım adım ayar. HTTP ile gönderim için token da burada. |
| **Konum ve başlık** | Haritadaki hedef nokta (hazır şehirler ya da enlem/boylam) |
| **Log kaynakları** | İzinli gönderici IP'leri/ağları, log türlerini açma/kapama, syslog portu, Suricata `eve.json` yolu |
| **GeoIP** | MaxMind bilgileri, *Şimdi indir*, haftalık otomatik güncelleme, `.mmdb` elle yükleme |
| **Görünüm ve erişim** | Ziyaretçiye göster / yalnızca üyeler, IP maskeleme, demo, saniyedeki en fazla yay, saklama süresi |

## CloudPanel'e özel notlar

- **Varnish Cache açıksa** CloudPanel → Site → Varnish Cache → *Excludes* bölümüne `/wp-json/` ekleyin. Eklenti zaten önbelleğe alınmaması gerektiğini bildirir ve her isteği farklı bir adresle yapar, ama bu kural işi garantiye alır.
- **PHP sürümü:** Servis komutu sitenizin PHP sürümünü kullanır (ör. `php8.3`). Siteyi başka bir PHP sürümüne geçirirseniz yönetim sayfasındaki komutu yeniden çalıştırın.
- **Eklentiyi güncellediğinizde** toplayıcıyı yeniden başlatın: `sudo systemctl restart threat-origin-map-<alanadınız>`. Tam komut yönetim sayfasında yazar.
- **Servis logları:** `journalctl -u threat-origin-map-<alanadınız> -f`
- **Cloudflare:** Alan adınız Cloudflare proxy arkasındaysa cihazlara alan adını değil, sunucunun gerçek IP'sini yazın. Cloudflare UDP iletmez.

## Hangi loglar haritaya düşer

| Kaynak | Alınan | Atlanan |
|---|---|---|
| pfSense / OPNsense `filterlog` | `block` + `in` | pass, dışarı giden |
| Suricata EVE | `event_type: alert` | flow, dns, http vb. |
| FortiGate | `action=deny/blocked/dropped…`, `subtype=ips/anomaly/waf/virus` | accept |

Özel, yerel ve ayrılmış IP'ler her zaman atlanır.

Saldırı türü önce IDS imzasına bakılarak belirlenir:

- Trojan → Malware/C2
- SQL → Web exploit

İmza yoksa hedef porta bakılır:

- 22/3389 → Brute force
- 80/443 → Web exploit
- UDP 53/123 → DoS
- Kalanı → Port scan

## Yük ve veritabanı

- **Sayaçlar:** Her olay sayılır. Sayaçlar dakikalık ve ülke × tür başına tek satırda tutulur.
- **Çizilen olaylar:** Ayrı bir tabloya en fazla *saniyedeki en fazla yay* kadar olay yazılır (varsayılan 40). Yoğun saldırıda veritabanı şişmez; haritada "High volume · map shows a sample" yazar.
- **Toplu yazma:** Toplayıcı saniyede bir, toplu INSERT ile yazar.
- **Harita güncellemesi:** Harita 2 saniyede bir yeni olayları çeker, sekme arka plandayken 15 saniyede bir. İstatistikler 2 saniye önbelleğe alınır.
- **Temizlik:** Eski olaylar her gün WP-Cron ile silinir (varsayılan 7 gün). Sitenize az ziyaretçi geliyorsa CloudPanel'de gerçek bir cron tanımlayın: `*/5 * * * * php8.3 /home/KULLANICI/htdocs/ALANADI/wp-cron.php`

## Kaldırma

Eklentiyi devre dışı bırakıp **Sil** dediğinizde tablolar, ayarlar ve GeoIP dosyası silinir. Toplayıcı servisini de kaldırın:

```bash
sudo systemctl disable --now threat-origin-map-<alanadınız>
sudo rm /etc/systemd/system/threat-origin-map-<alanadınız>.service
```

## Testler

```bash
php tests/test-core.php [GeoIP2-City-Test.mmdb]
```

Testler parser'ları, sınıflandırmayı, IP filtrelerini ve saf PHP ile yazılmış `.mmdb` okuyucuyu kontrol eder. MaxMind'ın test veritabanı: https://github.com/maxmind/MaxMind-DB/tree/main/test-data

Bu ürün GeoLite2 verisi kullanır (MaxMind, https://www.maxmind.com).
