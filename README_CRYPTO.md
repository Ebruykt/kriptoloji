# AES-DES-RSA Şifreli İstemci-Sunucu Haberleşme Sistemi

Bu proje, AES-128, DES ve RSA algoritmalarını kullanarak şifreli istemci-sunucu haberleşme sistemi içerir.

## Özellikler

- **AES-128**: Hem kütüphaneli hem de manuel implementasyon
- **DES**: Hem kütüphaneli hem de manuel implementasyon  
- **RSA**: Kütüphaneli implementasyon (anahtar dağıtımı için)
- **İstemci-Sunucu Haberleşmesi**: Şifreli mesajlaşma sistemi
- **Anahtar Yönetimi**: Otomatik anahtar üretimi ve saklama

## Kurulum

### Gereksinimler

```bash
pip install pycryptodome flask
```

veya

```bash
pip install -r requirements.txt
```

## Kullanım

### 1. Web Arayüzü (Flask)

Klasik şifreleme algoritmaları için web arayüzü:

```bash
python app.py
```

Tarayıcıda `http://localhost:5000` adresine gidin.

### 2. Şifreli İstemci-Sunucu Sistemi

#### Sunucuyu Başlatma

```bash
python crypto_server.py
```

Sunucu `127.0.0.1:12346` adresinde dinlemeye başlar.

#### İstemciyi Çalıştırma

Başka bir terminalde:

```bash
python crypto_client.py
```

İstemci interaktif modda çalışır:
- Algoritma seçimi (aes/des/rsa)
- Kütüphane kullanımı seçimi (e/h)
- Anahtar girişi (isteğe bağlı)
- Mesaj gönderme

## Algoritma Detayları

### AES-128

- **Anahtar uzunluğu**: 16 byte
- **Blok boyutu**: 16 byte
- **Mod**: CBC (kütüphaneli), ECB benzeri (manuel)
- **Manuel implementasyon**: S-box, ShiftRows, MixColumns, AddRoundKey işlemleri

### DES

- **Anahtar uzunluğu**: 8 byte
- **Blok boyutu**: 8 byte
- **Mod**: CBC (kütüphaneli), ECB benzeri (manuel)
- **Manuel implementasyon**: Feistel yapısı, S-box, permütasyonlar

### RSA

- **Anahtar boyutu**: 2048 bit (varsayılan)
- **Kullanım**: Anahtar dağıtımı ve şifreleme
- **Mod**: PKCS1_OAEP
- **Not**: Manuel implementasyon beklenmez, sadece kütüphane kullanılır

## Dosya Yapısı

```
.
├── crypto/
│   ├── aes.py              # AES-128 implementasyonu
│   ├── des.py               # DES implementasyonu
│   ├── rsa.py               # RSA implementasyonu
│   ├── key_manager.py       # Anahtar yönetimi
│   └── ...                  # Diğer klasik şifreleme algoritmaları
├── crypto_server.py         # Şifreli sunucu
├── crypto_client.py         # Şifreli istemci
├── app.py                   # Flask web uygulaması
└── requirements.txt         # Python bağımlılıkları
```

## Wireshark Analizi

Sistemi test ederken Wireshark kullanarak ağ trafiğini analiz edebilirsiniz:

1. Wireshark'ı başlatın
2. Loopback interface'i (lo) seçin
3. Filtre: `tcp.port == 12346`
4. Sunucu ve istemciyi çalıştırın
5. Paketleri yakalayın ve analiz edin

### Gözlemlenecekler

- **Şifreli payload**: TCP paketlerinde payload kısmı okunamaz olmalı
- **Paket boyutları**: 
  - AES/DES: Benzer boyutlar (padding ile)
  - RSA: Daha büyük paketler (asimetrik şifreleme nedeniyle)
- **Base64 encoding**: Şifreli veriler base64 ile kodlanmış olarak görünür

## Manuel vs Kütüphane Karşılaştırması

Manuel implementasyonlar öğrenme amaçlıdır ve:
- Algoritmanın iç yapısını gösterir
- S-box, permütasyon, round yapıları gibi kavramları öğretir
- Performans açısından kütüphaneli versiyonlardan daha yavaştır

Kütüphaneli versiyonlar:
- Üretim ortamında kullanılmalıdır
- Optimize edilmiş ve test edilmiştir
- Daha hızlı ve güvenlidir

## Notlar

- Manuel AES/DES implementasyonları basitleştirilmiş versiyonlardır (öğrenme amaçlı)
- RSA için manuel implementasyon beklenmez
- Anahtarlar `keys.json` dosyasında saklanır (güvenlik için şifrelenmemiştir - sadece test için)
- Üretim ortamında anahtar yönetimi için daha güvenli yöntemler kullanılmalıdır

## Lisans

Bu proje eğitim amaçlıdır.

