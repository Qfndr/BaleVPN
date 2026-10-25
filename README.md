# Bale VPN

**Security update 2.6.2:** fixes the vulnerable WebRTC/DTLS arithmetic dependency
chain (RUSTSEC-2026-0387) across desktop, headless and Android builds. See the
[security and upgrade notes](docs/security-dtls-2.6.2.md). Downloads include source
commit metadata, checksums and dependency audit evidence.

> 🟢 **Simplest start — two Android phones.** A peer-to-peer VPN over Bale messenger: one phone shares its working internet with the other, with no third-party server, no signup, and no command line. Install the APK on both, sign in with your Bale account in the app, flip one to **Server** and the other to **Client**.
>
> **→ [Android setup guide](docs/android-en.md)**

A peer-to-peer VPN that tunnels IP traffic over the voice-call infrastructure of [**Bale**](https://bale.ai/), the national Iranian messaging app. One device runs as the *server* (provides internet); another as the *client* (consumes it). To Bale's servers the link looks like a long voice call between two contacts.

The point: when one person has a working / uncensored connection and the other doesn't, the second person can route their traffic through the first — without any extra server, account, payment, or signup. Just install the app on two phones (or a laptop on the server side), make sure the two accounts have each other in their contact list, and connect.

There is no commercial relationship with Bale.

<div dir="rtl">

## دربارهٔ پروژه

> 🟢 **ساده‌ترین شروع — دو گوشی اندرویدی.** یک VPN نقطه‌به‌نقطه روی پیام‌رسان بله: یک گوشی، اینترنت سالمش را با گوشی دیگر به اشتراک می‌گذارد؛ بدون سرور خارجی، بدون ثبت‌نام، بدون خط فرمان. APK را روی هر دو نصب کنید، با حساب بلهٔ خودتان در اپ وارد شوید، یکی را روی **سرور** و دیگری را روی **کلاینت** بگذارید.
>
> **← [راهنمای نصب اندروید](docs/android-fa.md)**

برای اجرای برنامه روی سرور لینوکس خارج از کشور و اتصال از ویندوز، [راهنمای کامل راه‌اندازی و رفع خطاها](docs/linux-server-windows-client-fa.md) را بخوانید؛ شامل ورود، SSH، اتصال، تنظیم SOCKS5 و DNS، اجرای دائمی و به‌روزرسانی است.

اگر خود سرور لینوکس باید **کلاینت** باشد، [راهنمای کلاینت لینوکس](docs/linux-client-fa.md) شامل اجرای headless، پنل خصوصی با SSH، ورود یا انتقال نشست، جفت‌سازی، آزمون SOCKS5، اجرای پس‌زمینه و سرویس systemd است.

نسخهٔ تست ۲٫۶٫۳-dev.3، [اطلاعات حساب و تغییر پورت مستقل](docs/account-information-ports-fa.md) را کنار هر ردیف حساب اضافه می‌کند؛ برای تغییر پورت یک حساب، توقف حساب‌های دیگر لازم نیست. راهنمای [چند حساب روی دو VPS](docs/multi-account-vps-fa.md) هم چیدمان و تأیید جداگانهٔ تماس‌گیرندگان را توضیح می‌دهد.

نسخهٔ تست ۲٫۶٫۳-dev.4، [انتخاب مسیر تطبیقی و حالت تأخیر کمتر](docs/adaptive-pool-fa.md) را به تجمیع اضافه می‌کند؛ روش‌ها، محدودیت افزایش سرعت، منابع تحقیق و تست مقایسه‌ای در همین راهنما آمده‌اند. این قابلیت تجمیع بسته‌های یک جریان واحد نیست.

نسخهٔ تست ۲٫۶٫۳-dev.5، [پایش زندهٔ مجموع و هر مسیر تجمیع](docs/pool-live-telemetry-fa.md) شامل RTT تونل، افت اعلام‌شدهٔ QUIC، سرعت، حجم، کیفیت تشخیصی و نمودار قابل بررسی با ماوس و صفحه‌کلید را اضافه می‌کند. تفاوت پینگ، زمان برقراری SOCKS و دامنهٔ اندازه‌گیری در پنل توضیح داده می‌شود.

نسخهٔ تست ۲٫۶٫۳-dev.6، [باندینگ واقعیِ یک جریان TCP](docs/single-stream-bonding-fa.md) را به‌صورت اختیاری اضافه می‌کند: چند تونل با تأیید هویت، بازچینی و بازفرستادن محدود و یک سوکت TCP مقصد. راه‌اندازی به ارتقای هر دو سمت و فعال‌کردن رله در کنترل‌کنندهٔ مشترک سرور نیاز دارد؛ نتایج کنترل‌شده و محدودیت‌های تأخیر، حافظه و ظرفیت در راهنما آمده‌اند.

نسخهٔ ۲٫۶٫۱ گزینهٔ اختیاری [اتصال مجدد خودکار](docs/automatic-reconnect-fa.md) را برای هر حساب اضافه می‌کند؛ وقتی روشن است، پس از قطع ناخواسته یا دستی دوباره تلاش می‌کند و وقتی خاموش است، قطع می‌ماند.

رابط جدید نسخهٔ ۲٫۳ تب‌های مستقل اتصال، ترافیک، مدیریت کلاینت‌ها، امنیت، تنظیمات اتصال و شخصی‌سازی دارد؛ [راهنمای رابط تب‌بندی‌شده](docs/workspace-fa.md) را ببینید.

نسخهٔ ۲٫۶ سربرگ یکپارچه، مدیریت از ناحیهٔ اعلان و انتقال رمزگذاری‌شدهٔ نشست‌های فعلی را اضافه می‌کند؛ [راهنمای دسکتاپ و انتقال نشست‌ها](docs/desktop-session-transfer-fa.md) را ببینید.

نسخهٔ ۲٫۵ ورود و مدیریت چند حساب کلاینت را داخل همان پنجره و با زبان فارسی هماهنگ اضافه می‌کند. نسخهٔ ۲٫۴ تب اختیاری تجمیع چند تونل با حالت‌های کمترین بار، نوبتی و مسیر پشتیبان دارد. برای ساخت دو مسیر مستقل با چهار حساب روی ویندوز و یک VPS، [راهنمای تجمیع تونل‌ها](docs/multi-tunnel-fa.md) را بخوانید. این قابلیت اتصال‌های TCP جدا را تقسیم می‌کند؛ یک جریان تک‌اتصالی را تجمیع نمی‌کند و افزایش سرعت تضمینی نیست.

این پروژه یک VPN نقطه‌به‌نقطه است که ترافیک IP را روی زیرساخت تماس صوتی [**بله**](https://bale.ai/)، پیام‌رسان ملی ایران، عبور می‌دهد. یک دستگاه نقش *سرور* را دارد (اینترنت می‌دهد) و دستگاه دیگر نقش *کلاینت* را (اینترنت می‌گیرد). برای سرورهای بله این ارتباط شبیه یک تماس صوتی طولانی بین دو مخاطب به نظر می‌رسد.

هدف: وقتی یک نفر اینترنت سالم دارد و نفر دیگر نه، نفر دوم بدون هیچ سرور یا اشتراک اضافه‌ای می‌تواند ترافیکش را از طریق نفر اول رد کند. فقط کافی است هر دو طرف، هم در بله ثبت‌نام کرده باشند و هم یکدیگر را در فهرست مخاطبین داشته باشند.

این پروژه هیچ ارتباط تجاری‌ای با بله ندارد.

</div>

---

## ⚠️ Privacy & encryption

The Rust desktop/headless **2.6.2 build** requires authenticated
SOCKS5 encryption by default. Both devices keep a private TLS identity and
exchange public pairing codes through a trusted channel, such as SSH. TLS 1.3
inside QUIC verifies both certificates and handshake signatures. Unpaired peers
are rejected, and the app does not silently downgrade to the old protocol.
See the [Persian secure setup guide](docs/secure-pairing-fa.md).

The WebRTC carrier uses DTLS-SRTP through Bale's SFU. Authenticated QUIC protects
SOCKS5 contents between the paired client and server even against an active
relay without the paired private keys. The exit server decrypts the tunnel;
use HTTPS for the server-to-destination leg. This is not an anonymity guarantee:
Bale still sees the accounts, call existence, connection IPs, timing and volume.
Local call limits are safeguards, not a guarantee against account restrictions.

**Legacy and raw-IP modes:** older builds, Android's current unpaired path,
and explicitly selected compatibility mode do not authenticate the QUIC peer.
Raw IP mode is not end-to-end encrypted against the SFU. The authenticated
2.2 desktop path disables raw IP/TUN rather than leave an authentication bypass.
Do not treat those older modes as equivalent to verified pairing.

Windows protects stored tokens and private identities with user-bound DPAPI.
Linux uses AES-256-GCM with a private key file or an externally supplied/systemd
credential key. A local key backed up alongside its ciphertext does not protect
against theft of the whole folder. Keep data and backups private; see the guide
for migration, recovery limits, and external-key setup.

## ⚠️ Responsible use

This tool is meant for **normal interactive internet use** — web browsing, messaging, email, light app usage. **Not** for video streaming, large downloads, torrents, or other sustained high-bandwidth workloads.

The tunnel rides on Bale's LiveKit infrastructure. Heavy traffic from a "voice call" stands out on Bale's metrics, strains their servers, and makes the project easier to detect and shut down for everyone. **Use responsibly — don't ruin it for the next person.**

<div dir="rtl">

### ⚠️ استفادهٔ مسئولانه

این ابزار برای **استفادهٔ معمولی و تعاملی از اینترنت** ساخته شده — مرور وب، پیام‌رسان‌ها، ایمیل، استفادهٔ سبک از اپ‌ها. **برای استریم ویدیو، دانلودهای حجیم، تورنت یا سایر بارهای پربازده پایدار طراحی نشده.**

تونل روی زیرساخت LiveKit بله اجرا می‌شود. ترافیک سنگین از یک «تماس صوتی» در متریک‌های بله جلب توجه می‌کند، فشار روی سرورهایشان می‌گذارد، و تشخیص و خاموش کردن پروژه را برای همه آسان‌تر می‌کند. **مسئولانه استفاده کنید — حق نفر بعدی را پایمال نکنید.**

</div>

---

## Supported features

| Role | Platform | Notes |
|---|---|---|
| Client | Android | System `VpnService` (kernel TUN). Optional LAN-facing SOCKS5 listener in **Advanced** settings lets other devices on the local network share the tunnel. |
| Server | Android | In-process userspace TCP/IP NAT; no root, no kernel TUN, no `iptables`. |
| Client | Rust — Linux / macOS / Windows | Local SOCKS5 listener over a QUIC channel (no privilege needed). Optional system TUN (`--client-tun`, Linux/macOS only) for full host routing. |
| Server | Rust — Linux | **Kernel TUN** mode (best throughput) needs `setcap cap_net_admin` + `iptables` MASQUERADE — one-time setup. **Userspace NAT** mode runs unprivileged. |
| Server | Rust — macOS | **Kernel TUN** mode (best throughput) runs as root; `pf` anchor + IP forwarding auto-set. **Userspace NAT** mode runs unprivileged. |
| Server | Rust — Windows | Userspace NAT mode only. |

> **Easiest start: Android server + Android client.** Two phones, install the APK on both, sign in with your Bale account in the BaleVPN app, flip the toggle. No root, no command line, no firewall rules.
>
> **Most efficient: Linux or macOS Rust kernel-TUN server + Android client.** The kernel does the IP forwarding (TUN device) and the NAT (`iptables` MASQUERADE on Linux, `pf` anchor on macOS) — substantially faster than the userspace alternatives. The Android client connects via the standard `VpnService` for a fully-integrated system VPN.

The Rust server's forwarding mode is selectable at startup via `--nat-mode kernel|userspace`. `kernel` requires the one-time setup linked above; `userspace` runs with no privilege on any OS.

---

## Detailed guides

For a Linux server and Windows client, see the [complete Persian walkthrough](docs/linux-server-windows-client-fa.md): file setup, SSH access to the server UI, login, peer approval, SOCKS5/DNS, systemd, updates, and troubleshooting.

Per-platform setup, manuals, and screenshots:

| Platform | English | فارسی |
|---|---|---|
| **Android** (client and userspace-TCP/IP server) | [Android user guide](docs/android-en.md) | [راهنمای کاربری اپلیکیشن اندروید](docs/android-fa.md) |
| **Rust** — Linux / macOS / Windows (client + server; kernel TUN on Linux/macOS, userspace NAT on any OS) | [Rust application guide](docs/rust-en.md) | [راهنمای نسخهٔ Rust](docs/rust-fa.md) |

For contributors:
- [`docs/architecture.md`](docs/architecture.md) — repo layout, crate dependency graph, runtime data flow, build steps per component, CI workflows.
- [`CLAUDE.md`](CLAUDE.md) — protocol internals, wire formats, and Bale-specific decisions.

---

## Architecture

```
        ┌──────────────────────────────────────────────────────────────┐
        │   Bale signaling WS  ·  wss://next-ws.bale.ai/ws/            │
        │   call setup (StartCall / AcceptCall / DiscardCall),         │
        │   presence, callReceived / callEnded push events             │
        └────┬─────────────────────────────────────────────────┬───────┘
             │ signaling                                signaling
             │ (paused while a client call is active)          │
             ▼                                                 ▼
    ┌──────────────────────┐            ┌───────────────────────┐
    │        client        │            │        server         │
    │    Rust / Android    │            │    Rust / Android     │
    │                      │            │                       │
    │ apps → SOCKS5 → QUIC │            │ QUIC → SOCKS5 fan-out │
    │ apps → TUN (raw IP)  │            │ raw IP → TUN / NAT    │
    └──────────┬───────────┘            └───────────┬───────────┘
               │                                    │
               └─────────────────┬──────────────────┘
                                 │
             WebRTC RTP media carrier (Opus / SRTP)
               ▶ 'I'  raw IP packets   (TUN / VPN mode)
               ▶ 'Q'  QUIC datagrams   (carry SOCKS5 streams)
                                 │
                                 ▼
                  ┌────────────────────────────────────┐
                  │   LiveKit SFU  ·  meet-*.ble.ir    │
                  │   relays the RTP media carrier —   │
                  │   does NOT touch the open internet │
                  └────────────────────────────────────┘
                                                          ┌──────────┐
   server egress: QUIC → host sockets, raw IP → NAT ────► │   open   │
                                                          │ internet │
                                                          └──────────┘
```

**Transport — a WebRTC RTP media carrier (Opus over SRTP), on the pure-Rust `webrtc-rs` stack.** Each peer runs the two-PeerConnection model (publisher + subscriber). Tunnel bytes are written **directly** as the RTP payload of an "audio" track (`write_sample`) — no codec, no data channel; the SFU sees opaque Opus RTP and relays it, and the far end reads the bytes straight off `read_rtp`. RTP-over-SRTP is structurally indistinguishable from an ordinary voice call and survives DPI that fingerprints SCTP data channels. Writing the payload ourselves (instead of through an encoder) also removes the per-track bitrate ceiling a real codec would impose.

A single leading byte tags each frame, selecting one of **two modes** that can run concurrently on the same tunnel:

- `'I'` (0x49) — **VPN / TUN mode (raw IP).** The client's kernel TUN reads IP packets → ships them across → the server forwards them via kernel TUN (host-kernel NAT: iptables MASQUERADE / pf) or userspace NAT (per-flow Rust TCP/UDP state machines). The RTP carrier is lossy, so the guest's own TCP handles any retransmission end-to-end.
- `'Q'` (0x51) — **SOCKS5 over QUIC.** Because the RTP carrier is lossy (best-effort, like UDP), the SOCKS5 path runs a **QUIC** connection layered on top of it to get reliability + congestion control: the client's local SOCKS5 listener feeds each proxied TCP connection into a QUIC stream → quinn's datagrams cross the carrier as `'Q'` frames → the server's QUIC acceptor demuxes the streams and opens a host socket per SOCKS5 dial. So QUIC is the transport that carries SOCKS5; the RTP carrier just ferries QUIC's datagrams.

Apps choose between them by configuring SOCKS5 vs. using the system VPN route.

**Server NAT** owns egress to the open internet. The SFU only relays the media carrier; it never sees the unwrapped tunnel data and doesn't route to the internet itself.

**Privacy.** Use authenticated pairing in the 2.2 desktop test build. Legacy/raw-IP paths retain their older threat model; use HTTPS in every mode. See the [privacy note](#%EF%B8%8F-privacy--encryption) and [secure setup](docs/secure-pairing-fa.md).

---

## Status

Active research / experimentation. APIs and on-disk formats may change without notice.

---

## Disclaimer

This is an independent reverse-engineering **research project**. There is no commercial relationship with, and no endorsement by, Bale or any of its operators. The code is published for educational purposes — to document how a closed-source messenger's WebRTC voice-call infrastructure can be repurposed as a generic data tunnel, and to make the wire formats and protocols involved legible to other researchers.

**You are responsible for how you use this software.** The author(s):

- make no warranty of any kind, express or implied, including merchantability, fitness for a particular purpose, security, or compliance with any local law or regulation;
- accept no liability for any damages, claims, costs, or losses arising from use, misuse, or inability to use this software;
- accept no responsibility for any violation of Bale's terms of service, of any applicable telecommunications, privacy, or computer-access laws, or of any third-party rights, that may arise from running this software.

Only use it on accounts and infrastructure you own or have explicit permission to test against. Do not use it to circumvent access controls you have not been authorised to bypass, to evade lawful network policy, or to harm any third party.

If you are unsure whether your intended use is lawful in your jurisdiction, consult a qualified lawyer before proceeding.

---

## License

Released under the [MIT License](LICENSE). The software is provided "as is", without warranty of any kind. The disclaimer above applies in addition to (not in place of) the license terms.
