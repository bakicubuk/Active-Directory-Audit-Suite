# Active Directory Audit Suite

Bir Active Directory ortamını **salt okunur** olarak denetleyen, her modülü tek başına çalışan
ve **tek parça, çevrimdışı, interaktif HTML raporu** üreten PowerShell script koleksiyonu.

Tüm sorgular yalnızca okuma yapar; hiçbir nesne (kullanıcı, GPO, trust, DC) değiştirilmez.
Üretilen raporlar kendi kendine yeter (self-contained): telemetri yoktur, dışarıya veri gönderilmez,
seçtiğiniz çıktı klasörü dışında hiçbir yere yazılmaz.

> **Yazar:** Baki CUBUK · **Lisans:** MIT

---

## İçindekiler

- [1. Scriptler ne yapar](#1-scriptler-ne-yapar)
- [2. Önkoşullar](#2-önkoşullar)
- [3. GitHub'dan indirme ve çalıştırma](#3-githubdan-indirme-ve-çalıştırma)
- [4. Manuel (ZIP) indirme ve çalıştırma](#4-manuel-zip-indirme-ve-çalıştırma)
- [5. Parametreler](#5-parametreler)
- [6. Raporları okuma: her modülde nelere dikkat edilmeli](#6-raporları-okuma-her-modülde-nelere-dikkat-edilmeli)
- [7. Regülasyon ve uyumluluk (KVKK / ISO 27001 / CIS)](#7-regülasyon-ve-uyumluluk-kvkk--iso-27001--cis)
- [8. Sık karşılaşılan sorunlar](#8-sık-karşılaşılan-sorunlar)
- [9. Güvenlik ve gizlilik notu](#9-güvenlik-ve-gizlilik-notu)

---

## 1. Scriptler ne yapar

Depoda `scripts/` klasörü altında altı bağımsız modül bulunur. Hepsini çalıştırmak zorunda
değilsiniz; her biri kendi başına anlamlı bir rapor üretir.

| # | Script | Ne yapar | Ürettiği rapor |
|---|--------|----------|----------------|
| 1 | **AD-Overview.ps1** | Forest'ın üst düzey özeti: forest/domain fonksiyonel seviyeleri, şema sürümü, FSMO rol sahipleri, tombstone lifetime; kullanıcı/bilgisayar/grup/OU/GPO sayıları; hesap durumu (etkin, devre dışı, eski, kilitli, parolası hiç dolmayan); bilgisayar OS dağılımı; grup dağılımı. | `AD_Overview_<tarih>.html` |
| 2 | **AD-Topology.ps1** | Forest → domain → site → DC hiyerarşisini interaktif harita olarak çizer. FSMO rolleri, subnetler, site-link'ler, replikasyon sağlığı (`repadmin`/`dcdiag` mantığı), DC kaynak kullanımı; her DC sağlığına göre renklenir. | `AD_Topology_<tarih>.html` |
| 3 | **AD-DCInventory.ps1** | Forest'taki her domain controller'ın envanteri: OS/build, IPv4, site, GC/RODC, uptime, erişilebilirlik; CIM/WMI ile donanım (üretici/model/BIOS, CPU, RAM, diskler, NIC'ler) ve performans (CPU/RAM kullanımı, NTDS.dit boyutu). | `AD_DCInventory_<tarih>.html` |
| 4 | **AD-CredentialHygiene.ps1** | Parola/lockout politikası puanlaması, Fine-Grained Password Policy'ler (PSO), gMSA/sMSA managed account'lar, LAPS kapsamı, riskli hesaplar (parola süresiz, delegation, SID history, eski servis parolaları, SPN'ler), krbtgt parola yaşı. Kategoriler CSV olarak indirilebilir. | `AD_AccountSecurity_<tarih>.html` |
| 5 | **AD-TrustRelationships.ps1** | Her AD trust'ını keşfeder: yön, tip, transitivity; güvenlik durumu (SID filtering, selective authentication, TGT delegation, AES/SHA); yaş ve bağlantı testi. Riskleri türetir (örn. external trust'ta SID filtering kapalı → yüksek risk). | `AD_TrustRelationships_<tarih>.html` |
| 6 | **GPO-PolicyAnalyzer.ps1** | Microsoft Policy Analyzer'ın manuel işini otomatikleştirir: her GPO'yu yedekler, ham `Registry.pol` + `GptTmpl.inf` dosyalarını ADMX/ADML ile anlaşılır policy isimlerine çözer ve tüm GPO'ları tek karşılaştırma tablosunda çakışmaları (conflict) işaretleyerek gösterir. | `GPO_PolicyAnalysis_<tarih>.html` + `GPOBackups/` |

**Ortak özellikler:** Tüm modüller salt okunurdur, çıktı olarak dark/light temalı tek bir HTML
dosyası üretir, harici bağımlılık gerektirmez ve tamamlandığında raporu varsayılan tarayıcıda açar
(`-OpenReport:$false` ile kapatılabilir).

---

## 2. Önkoşullar

| Gereksinim | Detay |
|-----------|-------|
| **İşletim sistemi** | Windows 10/11 veya Windows Server (2016+ önerilir). |
| **PowerShell** | 5.1 (Windows PowerShell) veya PowerShell 7+. |
| **RSAT – ActiveDirectory modülü** | Zorunlu (5 modül). `Import-Module ActiveDirectory` çalışmalı. |
| **RSAT – GroupPolicy modülü (GPMC)** | Yalnızca `GPO-PolicyAnalyzer.ps1` için. |
| **Domain'e katılım** | Domain-joined bir makineden çalıştırın. |
| **Yetki** | AD'ye **okuma** yetkisi olan bir domain hesabı yeterlidir. DC donanım/performans (DCInventory) ve bazı güvenlik alanları için **Domain Admin** ya da eşdeğer yetki daha eksiksiz sonuç verir. |
| **Ağ erişimi (opsiyonel)** | DCInventory'nin donanım/performans toplaması için DC'lere WinRM veya WMI/DCOM erişimi. Erişilemezse alanlar "Unavailable" gösterilir, script hata vermez. |

**RSAT nasıl kurulur?**

Windows 10/11 (yönetici PowerShell):

```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

Windows Server (yönetici PowerShell):

```powershell
Install-WindowsFeature RSAT-AD-PowerShell, GPMC
```

Modülün yüklendiğini doğrulayın:

```powershell
Import-Module ActiveDirectory ; Get-ADDomain
```

---

## 3. GitHub'dan indirme ve çalıştırma

Bilgisayarında **Git yüklüyse** en pratik yol budur (`git --version` çalışıyorsa yüklüdür):

```powershell
# 1) Depoyu indir
git clone https://github.com/<KULLANICI-ADIN>/AD-Assessment.git

# 2) Klasöre gir
cd AD-Assessment

# 3) Bir modülü çalıştır (ExecutionPolicy'yi tek seferlik bypass ederek)
powershell -ExecutionPolicy Bypass -File .\scripts\AD-Overview.ps1
```

> `git : The term 'git' is not recognized...` hatası alıyorsan Git yüklü değildir.
> Ya [git-scm.com/download/win](https://git-scm.com/download/win) adresinden kurabilir,
> ya da aşağıdaki **manuel (ZIP)** yöntemini kullanabilirsin — Git gerektirmez.

---

## 4. Manuel (ZIP) indirme ve çalıştırma

Git kurmak istemiyorsan:

1. Depo sayfasında yeşil **`< > Code`** düğmesine tıkla → **Download ZIP**.
2. İnen `AD-Assessment-main.zip` dosyasına **sağ tıkla → Properties (Özellikler)**.
   Altta **"Unblock / Engellemeyi kaldır"** kutusu varsa işaretle → **OK**.
   *(İnternetten inen dosyalar "bloklanmış" gelir; bu adım scriptlerin çalışmasını engelleyen
   uyarıyı kaldırır.)*
3. Sağ tıkla → **Extract All (Tümünü Ayıkla)**.
4. **PowerShell'i yönetici olarak** aç, ayıkladığın klasöre gidip modülü çalıştır:

```powershell
# Örnek: İndirilenler klasörüne ayıkladıysan
cd "$env:USERPROFILE\Downloads\AD-Assessment-main"

powershell -ExecutionPolicy Bypass -File .\scripts\AD-Overview.ps1
```

**Klasör yolunu bilmiyorsan:** Dosya Gezgini'nde ayıkladığın klasörü aç, üstteki adres çubuğuna
tıkla, tam yolu kopyala ve `cd "buraya yapıştır"` şeklinde kullan.

### Tek tek çalıştırma komutları

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\AD-Overview.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\AD-Topology.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\AD-DCInventory.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\AD-CredentialHygiene.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\AD-TrustRelationships.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\GPO-PolicyAnalyzer.ps1
```

### Raporları belirli bir klasöre toplamak

```powershell
# Önce klasörü oluştur, sonra hepsini oraya yönlendir
New-Item -ItemType Directory C:\ADReports -Force

.\scripts\AD-Overview.ps1            -OutputPath C:\ADReports
.\scripts\AD-Topology.ps1            -OutputPath C:\ADReports
.\scripts\AD-DCInventory.ps1         -OutputPath C:\ADReports
.\scripts\AD-CredentialHygiene.ps1   -OutputPath C:\ADReports
.\scripts\AD-TrustRelationships.ps1  -OutputPath C:\ADReports
.\scripts\GPO-PolicyAnalyzer.ps1     -OutputPath C:\ADReports
```

> **Not:** Scriptleri `C:\Windows\System32` içinden çalıştırmayın. "Yönetici olarak PowerShell"
> varsayılan olarak orada açılır; önce `cd` ile scriptlerin bulunduğu klasöre geçin. (GPO modülü
> bu durumu algılayıp çıktıyı `ProgramData` altına yönlendirir, ama yine de proje klasöründen
> çalıştırmak en temizidir.)

---

## 5. Parametreler

Ortak parametreler tüm modüllerde bulunur; modüle özel olanlar ayrıca belirtilmiştir.

| Parametre | Modül(ler) | Açıklama | Varsayılan |
|-----------|-----------|----------|-----------|
| `-OutputPath <klasör>` | Tümü | HTML raporunun (ve varsa CSV/yedeklerin) yazılacağı klasör. | Geçerli dizin |
| `-OpenReport:$false` | Tümü | Bittiğinde raporu tarayıcıda otomatik açma. | Açar (`$true`) |
| `-StaleDays <gün>` | Overview | Bir hesabın "eski (stale)" sayılması için gereken oturum-açmama süresi. | 180 |
| `-SkipHardware` | DCInventory | DC başına CIM/WMI donanım+performans toplamasını atla (daha hızlı). | Kapalı |
| `-InactiveDays <gün>` | CredentialHygiene | Etkin kullanıcının pasif sayılacağı süre. | 90 |
| `-StaleComputerDays <gün>` | CredentialHygiene | Bilgisayarın eski sayılacağı süre. | 90 |
| `-ServiceAccountStalePasswordDays <gün>` | CredentialHygiene | Servis hesabı parolasının eski sayılacağı yaş. | 365 |
| `-TestConnectivity:$false` | TrustRelationships | Trust partner bağlantı testini atla. | Test eder |
| `-ReplDelayInterSiteHours <saat>` | Topology | Site-ler arası replikasyonun "gecikmiş" sayılacağı eşik. | 6 |
| `-SkipExport` | GPO-PolicyAnalyzer | GPO'ları yeniden yedekleme; mevcut `GPOBackups`'ı yeniden analiz et. | Yedekler |
| `-GPONames "A","B"` | GPO-PolicyAnalyzer | Yalnızca belirtilen GPO'ları analiz et. | Tüm GPO'lar |

**Örnekler:**

```powershell
# Donanım toplamayı atlayarak hızlı DC envanteri
.\scripts\AD-DCInventory.ps1 -SkipHardware

# Eski hesap eşiğini 90 güne düşürerek genel bakış
.\scripts\AD-Overview.ps1 -StaleDays 90

# GPO'ları bir kez yedekleyip sonra tekrar tekrar hızlı analiz
.\scripts\GPO-PolicyAnalyzer.ps1
.\scripts\GPO-PolicyAnalyzer.ps1 -SkipExport
```

---

## 6. Raporları okuma: her modülde nelere dikkat edilmeli

Raporlar bilgi verir; **karar ve düzeltme sizindir**. Aşağıdakiler tipik "kırmızı bayrak"lardır.

### AD-Overview
- **Şema/fonksiyonel seviye:** Windows Server 2008/2012 gibi eski seviyeler modern güvenlik
  özelliklerini engeller — yükseltme planlayın.
- **Parolası hiç dolmayan hesaplar** ve **kilitli hesaplar:** Sayı yüksekse politika gözden geçirilmeli.
- **Eski (stale) hesaplar / hiç oturum açmamış hesaplar:** Kullanılmayan kimlikler saldırı yüzeyidir;
  devre dışı bırakma/silme süreci kurun.
- **Legacy OS dağılımı:** Desteği biten Windows sürümleri acil önceliktir.

### AD-Topology
- **Replikasyon gecikmesi / hatası (kırmızı DC):** En kritik bulgudur — DC'ler arası tutarsızlık
  kimlik doğrulama ve GPO uygulamasını bozar.
- **Tek FSMO sahibi / tek GC:** Tek nokta hata riski; yedeklilik planlayın.
- **Erişilemeyen DC:** Kapalı mı, ağ mı, gerçekten arızalı mı — teyit edin.

### AD-DCInventory
- **Desteği biten OS (2008/2012) üzerinde çalışan DC'ler:** Yükseltme önceliği.
- **Düşük disk boşluğu (özellikle NTDS.dit/log sürücüsü):** AD veritabanı dolabilir → servis kesintisi.
- **Yüksek CPU/RAM kullanımı veya çok kısa uptime:** Kararsızlık işareti olabilir.
- **"Unavailable" alanlar:** WinRM/DCOM erişimi yok demektir; güvenlik açığı değil, veri eksikliğidir.

### AD-CredentialHygiene (en yoğun güvenlik modülü)
- **Zayıf parola/lockout politikası puanı:** Baseline'ın altındaki her madde düzeltilmeli.
- **krbtgt parola yaşı yüksek:** Golden Ticket riskini azaltmak için düzenli rotasyon (iki kez) yapın.
- **Unconstrained delegation / SID history:** Yüksek riskli; iz sürüp kaldırın.
- **LAPS kapsamı eksik bilgisayarlar:** Yerel yönetici parolası yönetimi tam olmalı.
- **Eski servis hesabı parolaları + SPN'ler:** Kerberoasting hedefi; gMSA'ya geçmeyi değerlendirin.

### AD-TrustRelationships
- **External/forest trust'ta SID filtering DEVRE DIŞI → yüksek risk:** SID history ile ayrıcalık
  yükseltme mümkün olur; quarantine (SID filtering) etkinleştirin.
- **Selective authentication kapalı external trust:** Maruziyeti artırır.
- **Eski / kullanılmayan trust'lar:** Gerekçesi yoksa kaldırın.

### GPO-PolicyAnalyzer
- **Conflict (çakışma) işaretli satırlar:** Farklı GPO'lar aynı ayarı farklı değerlerle set ediyor —
  hangisinin kazandığı öncelik sırasına bağlıdır, sürprizlere yol açar.
- **Güvenlik baseline sapmaları:** Beklenen sertleştirme ayarlarının uygulanmadığı yerleri gösterir.
- **Çakışan/gereksiz GPO'lar:** Sadeleştirme fırsatı; daha az GPO = daha öngörülebilir sonuç.

---

## 7. Regülasyon ve uyumluluk (KVKK / ISO 27001 / CIS)

Bu araçlar bir **denetim/kanıt toplama (evidence)** aracıdır: bir sızma testi ya da resmi bir
uyumluluk sertifikası **değildir**, ancak birçok kontrolün kanıtını üretmenizi kolaylaştırır.
Aşağıdaki eşleme rehber niteliğindedir.

| Bulgu / Rapor alanı | ISO/IEC 27001:2022 (Annex A) | CIS Controls v8 | KVKK bağlamı |
|---------------------|------------------------------|-----------------|--------------|
| Eski/pasif/hiç kullanılmamış hesaplar (Overview, Credential) | A.5.16, A.5.18 (kimlik & erişim yönetimi) | 5 (Account Mgmt), 6 (Access Control) | "Kişisel veriye erişimi kişilerle sınırlama" ilkesi; gereksiz erişimlerin kaldırılması |
| Parola/lockout politikası, PSO (Credential) | A.5.17 (kimlik doğrulama bilgisi) | 5.2 (güçlü parola politikası) | İdari/teknik tedbir olarak kimlik doğrulama güvenliği (m.12) |
| krbtgt yaşı, delegation, SID history, Kerberoasting (Credential) | A.8.2, A.8.5 (ayrıcalıklı erişim, güvenli kimlik doğrulama) | 4 (Secure Config), 6 | Yetkisiz erişimi önlemeye yönelik teknik tedbirler |
| Trust güvenliği: SID filtering, selective auth (Trust) | A.5.19-A.5.22 (tedarikçi/harici ilişkiler), A.8.20-A.8.22 (ağ güvenliği) | 12 (Network Infra Mgmt) | Harici taraflarla veri paylaşımının güvence altına alınması |
| GPO sertleştirme & çakışmalar (GPO Analyzer) | A.8.9 (yapılandırma yönetimi) | 4 (Secure Configuration) | Sistemlerin güvenli yapılandırılması (teknik tedbir) |
| DC envanteri, OS desteği, disk sağlığı (DCInventory, Topology) | A.8.8 (teknik açıkların yönetimi), A.8.6 (kapasite) | 1-2 (asset envanteri), 7 (Vuln Mgmt) | Sistem envanteri ve güncel tutma yükümlülüğü |
| Replikasyon/sağlık, yedeklilik (Topology) | A.8.14 (bilgi işleme tesislerinin yedekliliği) | 11 (Data Recovery) | Verinin erişilebilirliği ve süreklilik tedbiri |

**Uyumluluk için önerilen döngü:**

1. **Referans (baseline) al:** Tüm modülleri çalıştırıp raporları tarih damgasıyla arşivleyin.
2. **Bulguları önceliklendir:** Önce yüksek riskli maddeler (SID filtering kapalı, desteği biten DC OS,
   unconstrained delegation, krbtgt eski).
3. **Düzelt ve belgele:** Her düzeltme için sorumlu + tarih + gerekçe kaydı tutun (denetim izi).
4. **Periyodik tekrar:** Aylık/çeyreklik yeniden çalıştırıp önceki raporla karşılaştırın; iyileşmeyi
   raporlarla kanıtlayın.
5. **Erişimi kısıtla:** Raporlar hassas topoloji ve hesap bilgisi içerir — erişim yetkili kişilerle
   sınırlı, şifreli bir konumda saklansın (bkz. Bölüm 9).

> **Önemli:** Uyumluluk hukuki bir değerlendirmedir. Bu eşleme teknik bir başlangıç noktasıdır;
> resmi uyumluluk için kurumunuzun bilgi güvenliği / hukuk birimiyle birlikte değerlendirin.

---

## 8. Sık karşılaşılan sorunlar

| Belirti | Neden / Çözüm |
|---------|---------------|
| `git ... is not recognized` | Git yüklü değil. Manuel (ZIP) yöntemini kullan veya Git'i kur. |
| `... cannot be loaded because running scripts is disabled` | ExecutionPolicy engeli. Komutu `powershell -ExecutionPolicy Bypass -File ...` şeklinde çalıştır. |
| `ActiveDirectory module not available` | RSAT-AD-PowerShell kurulu değil (Bölüm 2). |
| `GroupPolicy module not available` | GPO modülü için RSAT-GPMC gerekir (Bölüm 2). |
| `Could not contact the forest/domain` | Makine domain'e katılı değil ya da DC'ye ulaşılamıyor. Domain hesabıyla domain-joined makineden çalıştır. |
| Raporda çok sayıda "Unavailable" | DC'lere WinRM/DCOM erişimi veya yeterli yetki yok. Domain Admin ile ya da `-SkipHardware` olmadan dene. |
| Script `System32`'den açıldı | Önce `cd` ile proje klasörüne geç. |

---

## 9. Güvenlik ve gizlilik notu

- Bu scriptler **hiçbir değişiklik yapmaz** ve **hiçbir veriyi dışarı göndermez** — tüm işlem yereldir.
- Üretilen HTML/CSV raporları **hassas bilgi içerir** (hesap adları, DC isimleri, IP'ler, topoloji,
  güvenlik zayıflıkları). Bunları herkese açık paylaşmayın; erişimi kısıtlı, tercihen şifreli bir
  konumda saklayın.
- Raporları ve `GPOBackups/` klasörünü **repoya commit etmeyin** — `.gitignore` bunları zaten hariç tutar.
- Scriptleri yalnızca **yetkiniz olan** ortamlarda çalıştırın.

---

## Depo yapısı

```
AD-Assessment/
├── scripts/
│   ├── AD-Overview.ps1
│   ├── AD-Topology.ps1
│   ├── AD-DCInventory.ps1
│   ├── AD-CredentialHygiene.ps1
│   ├── AD-TrustRelationships.ps1
│   └── GPO-PolicyAnalyzer.ps1
├── .gitignore
├── LICENSE
└── README.md
```

---

*Active Directory Audit Suite — Baki CUBUK. MIT Lisansı ile dağıtılır. "AS IS" (olduğu gibi)
sağlanır; kullanım sorumluluğu kullanıcıya aittir.*
