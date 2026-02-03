# Keenetic Router Pro - Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/custom-components/hacs)
[![version](https://img.shields.io/badge/version-0.3.0-blue.svg)](https://github.com/)

Keenetic router'lar için gelişmiş Home Assistant entegrasyonu. Mesh ağ yönetimi, VPN kontrolü, cihaz takibi ve daha fazlası.

## 🌟 Özellikler

### 📡 Cihaz Takibi (Device Tracker)
- **ICMP Ping** ile gerçek zamanlı cihaz durumu
- Seçilebilir client listesi
- 5 saniye güncelleme aralığı
- IP değişikliklerinde otomatik güncelleme

### 🔗 Mesh Ağ Yönetimi
- Tüm extender/repeater durumları (binary sensor)
- Her mesh node için ayrı **reboot butonu**
- CPU, RAM, uptime bilgileri
- **Firmware güncelleme bildirimi** (update available sensörü)
- Bağlı client sayısı (associations)

### 🔐 VPN Yönetimi
- WireGuard profilleri aç/kapat (switch)
- OpenVPN, IPsec, L2TP, PPTP desteği
- VPN uptime, RX/TX sensörleri

### 📶 WiFi Kontrolü
- Her SSID için aç/kapat switch'i
- Guest WiFi kontrolü

### 🌐 WAN Durumu
- Gerçek **WAN IP adresi** (PPPoE destekli)
- Bağlantı durumu sensörü
- Uptime bilgisi

### 👥 Client Yönetimi
- Bağlı / bağlı olmayan cihaz sayısı
- **Connection Policy seçimi** (per-client)
  - Default, VPN, No VPN, Smart Home, Roblox, vb.
  - Deny (internet engelleme)
- Yeni cihaz bağlandığında **event** tetikleme

### 🔘 Butonlar
- Router reboot
- Mesh node reboot (her biri için ayrı)

---

## 📦 Kurulum

### HACS ile (Önerilen)

1. HACS > Integrations > ⋮ > Custom repositories
2. URL: `https://github.com/YOUR_USERNAME/keenetic_router_pro`
3. Category: Integration
4. "Keenetic Router Pro" ara ve yükle
5. Home Assistant'ı yeniden başlat

### Manuel Kurulum

1. `keenetic_router_pro` klasörünü `config/custom_components/` altına kopyala
2. Home Assistant'ı yeniden başlat

---

## ⚙️ Yapılandırma

### 1. Entegrasyonu Ekle

Settings > Devices & Services > Add Integration > **Keenetic Router Pro**

### 2. Bağlantı Bilgileri

| Alan | Açıklama | Örnek |
|------|----------|-------|
| Host | Router IP adresi | `192.168.1.1` |
| Port | Web arayüz portu | `80` veya `100` |
| Username | Admin kullanıcı adı | `admin` |
| Password | Admin şifresi | `********` |

### 3. Takip Edilecek Cihazları Seç

Kurulum sırasında hangi cihazların ping ile takip edileceğini seçebilirsin.

---

## 📊 Oluşturulan Entity'ler

### Sensörler (Sensors)

| Entity | Açıklama |
|--------|----------|
| `sensor.router_wan_ip` | WAN IP adresi |
| `sensor.router_wan_status` | WAN durumu (up/down) |
| `sensor.router_connected_clients` | Bağlı cihaz sayısı |
| `sensor.router_disconnected_clients` | Bağlı olmayan cihaz sayısı |
| `sensor.router_extenders` | Mesh extender sayısı |
| `sensor.mesh_*_firmware` | Mesh node firmware versiyonu |
| `sensor.wireguard_*_uptime` | VPN uptime |
| `sensor.wireguard_*_rx` | VPN indirilen veri |
| `sensor.wireguard_*_tx` | VPN yüklenen veri |

### Binary Sensörler

| Entity | Açıklama |
|--------|----------|
| `binary_sensor.mesh_*` | Mesh node bağlantı durumu |
| `binary_sensor.mesh_*_update_available` | Firmware güncelleme var mı |

### Switch'ler

| Entity | Açıklama |
|--------|----------|
| `switch.wifi_*` | WiFi SSID aç/kapat |
| `switch.wireguard_*` | WireGuard profili aç/kapat |
| `switch.vpn_*` | VPN tüneli aç/kapat |

### Butonlar

| Entity | Açıklama |
|--------|----------|
| `button.router_reboot` | Router'ı yeniden başlat |
| `button.mesh_reboot_*` | Mesh node'u yeniden başlat |

### Select (Seçim)

| Entity | Açıklama |
|--------|----------|
| `select.*_policy` | Client connection policy seçimi |

### Device Tracker

| Entity | Açıklama |
|--------|----------|
| `device_tracker.*` | Seçilen cihazların ping durumu |

---

## 🔔 Eventler

### `keenetic_router_pro_new_device`

Yeni bir cihaz ağa bağlandığında tetiklenir.

```yaml
automation:
  - alias: "Yeni Cihaz Bildirimi"
    trigger:
      - platform: event
        event_type: keenetic_router_pro_new_device
    action:
      - service: notify.mobile_app
        data:
          title: "🆕 Yeni Cihaz Bağlandı"
          message: "{{ trigger.event.data.name }} ({{ trigger.event.data.ip }})"
```

**Event Data:**
- `mac`: MAC adresi
- `name`: Cihaz adı
- `ip`: IP adresi
- `hostname`: Hostname
- `interface`: Bağlı olduğu interface
- `ssid`: WiFi SSID (varsa)

---

## 📝 Örnek Kullanımlar

### Dashboard Kartı

```yaml
type: entities
title: Router Durumu
entities:
  - entity: sensor.router_wan_ip
  - entity: sensor.router_connected_clients
  - entity: sensor.router_extenders
  - entity: button.router_reboot
```

### Mesh Durumu

```yaml
type: entities
title: Mesh Ağı
entities:
  - entity: binary_sensor.mesh_workroom_ultra
  - entity: binary_sensor.mesh_garden_buddy
  - entity: binary_sensor.mesh_garage_hopper
  - entity: binary_sensor.mesh_veranda_air
  - entity: binary_sensor.mesh_bedroom_air
```

### VPN Kontrolü

```yaml
type: entities
title: VPN
entities:
  - entity: switch.wireguard_zurich
  - entity: switch.wireguard_milano
  - entity: switch.wireguard_stockholm
```

### Çocuk İnternet Kontrolü

```yaml
type: entities
title: Çocuk Cihazları
entities:
  - entity: select.tablet_policy
  - entity: select.playstation_policy
  - entity: device_tracker.tablet
```

---

## 🌍 Dil Desteği

- 🇬🇧 English
- 🇹🇷 Türkçe
- 🇷🇺 Русский

---

## 🔧 Gereksinimler

- Home Assistant 2024.1.0 veya üzeri
- Keenetic router (NDMS 3.x / 4.x / 5.x)
- Router'da web yönetim arayüzü aktif olmalı

### Test Edilen Modeller

- Keenetic Ultra (KN-1810)
- Keenetic Hopper (KN-3810)
- Keenetic Buddy 5 (KN-3311)
- Keenetic Air (KN-1610)

---

## 🐛 Sorun Giderme

### Bağlantı Hatası

1. Router IP ve port doğru mu kontrol et
2. Kullanıcı adı/şifre doğru mu kontrol et
3. Router'da web arayüzü aktif mi kontrol et

### Entity'ler Görünmüyor

1. Home Assistant'ı yeniden başlat
2. Entegrasyonu kaldırıp tekrar ekle

### Ping Çalışmıyor

- Home Assistant'ın ICMP ping için yetkileri olmalı
- Docker kurulumlarında `network_mode: host` gerekebilir

---

## 📄 Lisans

MIT License

---

## 🤝 Katkıda Bulunma

Pull request'ler memnuniyetle karşılanır!

1. Fork et
2. Feature branch oluştur (`git checkout -b feature/amazing-feature`)
3. Commit et (`git commit -m 'Add amazing feature'`)
4. Push et (`git push origin feature/amazing-feature`)
5. Pull Request aç

---

## 📞 Destek

- [GitHub Issues](https://github.com/YOUR_USERNAME/keenetic_router_pro/issues)
- [Home Assistant Community](https://community.home-assistant.io/)

---

**⭐ Beğendiysen yıldız vermeyi unutma!**
