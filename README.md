# Threat Origin Map · Where attackers come from LIVE

Firewall / IDS cihazınızın engellediği bağlantıları ve IDS alarmlarını alır, saldırganın ülkesini bulur ve dünya haritasında canlı gösterir. Docker ile tek komutla kurulur. Kurulumdan sonra **bütün ayarlar web arayüzünden** yapılır.

```
pfSense / OPNsense / FortiGate / Suricata
        │  syslog (UDP 5514)   veya   eve.json
        ▼
   attack-map konteyneri ── GeoLite2 ile IP → ülke/konum
        │  canlı akış
        ▼
   Tarayıcı: harita · ilk 7 ülke · saldırı türleri · olay akışı · Ayarlar
```

## Kurulum

### Linux sunucu (önerilen)

```bash
sudo git clone https://github.com/demirozmustafa/attack-map.git /opt/attack-map
cd /opt/attack-map && sudo ./install.sh
```

**Güncelleme** (ayarlar, `.env` ve veriler korunur):

```bash
cd /opt/attack-map && sudo git pull && sudo ./install.sh
```

Betik:

1. Docker yoksa kurmayı önerir (resmi get.docker.com betiğiyle, siz onaylarsanız).
2. Üç soru sorar. Hepsi boş geçilebilir:
   - **Alan adı:** Girerseniz otomatik Let's Encrypt sertifikasıyla HTTPS kurulur. 80/443 portları sunucuya ulaşmalı.
   - **Syslog portu:** Varsayılan 5514.
   - **Suricata log klasörü:** Suricata aynı sunucudaysa.
3. Konteyneri derleyip başlatır, ufw açıksa gerekli portları açar.
4. Ekrana **harita adresini** ve **kurulum kodunu** yazar.

Soru sormadan varsayılanlarla kurmak için: `./install.sh -y`

Cevaplar `.env` dosyasına yazılır ve sonraki çalıştırmalarda yeniden sorulmaz. Alan adını, syslog portunu ya da Suricata klasörünü değiştirmek için: `./install.sh -r`

### Windows (Docker Desktop)

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Kurulum bitince tarayıcı kurulum sayfasını kendisi açar.

### Kurulum sihirbazı (tarayıcıda)

Adresi açınca sihirbaz gelir:

1. Kurulum kodu ve yönetici şifresi
2. Korunan konum (İstanbul, Ankara, Frankfurt… ya da enlem/boylam)
3. MaxMind GeoLite2 hesap bilgileri. İsterseniz sonra da girebilirsiniz.

Kurulum kodu, siz kurulumu bitirmeden başkasının paneli ele geçirmesini engeller. Kaybettiyseniz:

```bash
docker compose logs attack-map | grep "SETUP CODE"
```

## Ayarlar sayfası

| Bölüm | Ne yapılır |
|---|---|
| **Durum** | Log gönderen cihazlar, alınan/okunan satır sayıları, GeoIP durumu, *Test saldırısı gönder* düğmesi. İzinli listede olmayan bir cihaz log gönderirse burada görünür; **İzin ver** ile tek tıkla eklenir |
| **Cihaz bağlama** | pfSense, OPNsense, FortiGate ve Suricata için adım adım ayar. Sunucu adresi ve port hazır yazılı gelir, FortiGate CLI kopyalanabilir |
| **Konum** | Haritadaki hedef nokta ve adı |
| **Log kaynakları** | İzinli gönderici IP'leri/ağları, kaynak türlerini açma/kapama, Suricata `eve.json` yolu |
| **GeoIP** | MaxMind Account ID + License Key, *Şimdi indir*, haftalık otomatik güncelleme. İnternet yoksa `.mmdb` dosyasını elle yükleme |
| **Erişim** | Haritayı şifresiz gösterme (duvar ekranı için), demo verisi, saniyedeki en fazla yay sayısı |
| **Yönetici şifresi** | Şifre değiştirme. Diğer oturumlar kapanır |

Ayarlar Docker volume'unda (`attackmap-data`) saklanır. Güncelleme ya da yeniden başlatmada kaybolmaz.

## GeoIP (ücretsiz)

1. maxmind.com'da ücretsiz **GeoLite2** hesabı açın.
2. **Manage License Keys** bölümünden bir anahtar oluşturun.
3. Ayarlar → GeoIP'ye Account ID ve anahtarı girin, **Kaydet**'e ve ardından **Şimdi indir**'e basın.

Veritabanı haftada bir kendiliğinden güncellenir. GeoIP olmadan loglar alınır ama haritaya konamaz; harita üstünde bunu söyleyen bir uyarı çıkar.

## Hangi loglar haritaya düşer

| Kaynak | Alınan | Atlanan |
|---|---|---|
| pfSense / OPNsense `filterlog` | `block` + `in` (içeri gelen, engellenen) | pass, dışarı giden |
| Suricata EVE | `event_type: alert` | flow, dns, http vb. |
| FortiGate | `action=deny/blocked/dropped…`, `subtype=ips/anomaly/waf/virus` | accept |

Özel/iç IP'ler (10.x, 192.168.x, 172.16-31.x …) her zaman atlanır.

Saldırı türü önce IDS imza ve kategori metninden belirlenir:

- Trojan → Malware/C2
- SQL/HTTP → Web exploit
- DoS → DoS/flood

İmza yoksa hedef porta bakılır:

- 22, 3389, 23… → Brute force
- 80, 443 → Web exploit
- UDP 53, 123, 1900 → DoS/flood
- Kalanı → Port scan

## Günlük işler

```bash
./install.sh                         # güncelle (ayarlar korunur)
docker compose logs -f attack-map    # loglar
docker compose restart attack-map    # yeniden başlat
docker compose down                  # durdur (ayarlar volume'da kalır)
docker compose down -v               # her şeyi sil (ayarlar dahil)
```

Kurulumu sıfırdan yapmak için (şifreyi unuttuysanız): `docker compose down -v && ./install.sh`

**Web portu** varsayılan olarak **9595**'tir (`http://SUNUCU_IP:9595`). Değiştirmek için `.env` dosyasındaki `HTTP_PORT=` satırını düzenleyip `docker compose up -d` çalıştırın.

## Notlar

- **Gönderici IP'si:** Docker Desktop (Windows/Mac) UDP paketlerinin kaynak IP'sini değiştirebilir. Bu durumda Durum bölümünde cihaz farklı bir IP ile görünür; o IP'ye izin verin. Linux'ta gerçek IP görünür.
- **Suricata `eve.json` okuma izni:** Konteyner 10001 numaralı kullanıcıyla çalışır. `eve.json` yalnızca root tarafından okunabiliyorsa `chmod o+r` verin ya da syslog ile gönderin.
- **Ülke bilgisi:** Gösterilen ülke saldırganın gerçek yeri değil, IP'nin kayıtlı olduğu yerdir. VPN, Tor ve bulut sunucuları yaygındır.
- **Sayaçlar:** Bellekte tutulur. Konteyner yeniden başlarsa "Today" sıfırlanır.
- **İnternet gereksinimi:** Harita sayfası yazı tiplerini Google Fonts'tan, d3'ü jsDelivr'den yükler. İnternetsiz bir SOC ekranında bu dosyaların yerel kopyası gerekir.
- **Testler:** `python -m unittest test_parsers.py`
- **Lisans notu:** Bu ürün GeoLite2 verisi kullanır (MaxMind, https://www.maxmind.com).
