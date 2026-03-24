# acme-client-rs

[![CI](https://github.com/andrico21/acme-client-rs/actions/workflows/rust.yaml/badge.svg?branch=master)](https://github.com/andrico21/acme-client-rs/actions/workflows/rust.yaml)

Легковесный ACME-клиент в виде единого исполняемого файла, реализующий [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) с поддержкой [RFC 9702](https://www.rfc-editor.org/rfc/rfc9702) (ACME Renewal Information) и [DNS-PERSIST-01](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist). Полный жизненный цикл сертификата - от регистрации аккаунта до выпуска, продления и отзыва - в одном бинарнике размером ~2 МБ без внешних зависимостей.

Написан на Rust (редакция 2024) с `#![forbid(unsafe_code)]`, защищёнными release-сборками (CFG, ASLR, full RELRO, NX) и структурированным JSON-выводом для интеграции с CI/CD.

> **Раскрытие информации об ИИ:** Этот проект разработан с помощью ИИ - [Claude Opus 4.6](https://www.anthropic.com/claude) (через GitHub Copilot). Весь код, документация и тесты были проверены и утверждены автором.

## Возможности

- Полная реализация протокола RFC 8555: управление аккаунтами, ротация ключей, жизненный цикл заказов, обработка вызовов, загрузка сертификатов, отзыв
- Четыре типа вызовов: HTTP-01 (встроенный сервер или `--challenge-dir`), DNS-01 (интерактивный, hook-скрипты, автопроверка появления TXT-записи), DNS-PERSIST-01 (постоянные DNS-записи, [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist)), TLS-ALPN-01 (интерактивный)
- Привязка внешнего аккаунта (EAB) для CA, которые этого требуют в обязательном порядке (`--eab-kid` + `--eab-hmac-key`)
- Предварительная авторизация (RFC 8555 Section 7.4.1) через субкоманду `pre-authorize` или флаг `--pre-authorize` в `run`
- Универсальные hook-скрипты: `--on-challenge-ready` (вызывается после подготовки каждого вызова dns-01, dns-persist-01 или tls-alpn-01) и `--on-cert-issued` (вызывается после сохранения сертификата)
- Поддержка IP-идентификаторов (RFC 8738) с нормализацией IPv6 - автоматическое определение из аргументов командной строки
- Автоматизированный сквозной процесс (субкоманда `run`) со встроенным продлением (`--days N` пропускает запуск обновления, если срок продления ещё не наступил - отдельная команда renew не нужна)
- Защита от несовпадения доменов: обнаруживает, когда запрашиваемые домены отличаются от SAN существующего сертификата, предотвращает случайную перезапись (`--reissue-on-mismatch` для явного разрешения)
- ACME Renewal Information (ARI, RFC 9702): субкоманда `renewal-info` для запроса рекомендуемого окна продления от CA, и флаг `--ari` в `run` для использования серверного расписания продления с привязкой заказа через поле `replaces`
- Опциональное шифрование закрытого ключа (`--key-password` / `--key-password-file`) с использованием PKCS#8 + AES-256-CBC с KDF scrypt
- Пошаговый ручной процесс (отдельные субкоманды)
- Шесть алгоритмов ключей: ES256 (по умолчанию), ES384, ES512, RSA-2048, RSA-4096, Ed25519
- Настройка через флаги командной строки, конфигурационный файл или переменные окружения
- Флаг `--insecure` для тестирования с самоподписанными CA (например, Pebble)
- Чистые сообщения об ошибках (без стектрейсов для операционных ошибок)
- Структурированный JSON-вывод (`--output-format json`) для машинной обработки и CI/CD-пайплайнов

## Быстрый старт

```sh
# 1. Генерация ключа аккаунта (ES256 по умолчанию)
acme-client-rs generate-key

# 2. Запуск полного процесса с указанием сервера
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 your.domain.com

# 3. Продление - просто повторный запуск с --days (пропустит, если ещё не пора)
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 --challenge-dir /var/www/html --cert-output /etc/ssl/certs/your.domain.pem --key-output /etc/ssl/private/your.domain.key --days 30 your.domain.com
```

> **Совет:** Отдельной команды `renew` нет. Субкоманда `run` с `--days N` идемпотентна - проверяет существующий сертификат и обращается к CA только когда продление действительно необходимо. Безопасно вызывать из cron ежедневно.

### Алгоритмы ключей

```sh
# По умолчанию: ES256 (P-256)
acme-client-rs generate-key

# Другие алгоритмы
acme-client-rs generate-key --algorithm es384
acme-client-rs generate-key --algorithm es512
acme-client-rs generate-key --algorithm rsa2048
acme-client-rs generate-key --algorithm rsa4096
acme-client-rs generate-key --algorithm ed25519
```

### Алгоритм ключа сертификата

Закрытый ключ сертификата (используемый в CSR) отделён от ключа аккаунта. По умолчанию используется ECDSA P-256. Изменить можно с помощью `--cert-key-algorithm`:

```sh
# По умолчанию: ECDSA P-256
acme-client-rs run --cert-key-algorithm ec-p256 ...

# ECDSA P-384
acme-client-rs run --cert-key-algorithm ec-p384 ...

# Ed25519
acme-client-rs run --cert-key-algorithm ed25519 ...
```

Поддерживаемые значения: `ec-p256` (P-256/SHA-256, по умолчанию), `ec-p384` (P-384/SHA-384), `ed25519`.

### Вызов DNS-01

Три режима работы:

#### Интерактивный (по умолчанию)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 your.domain.com
```

Клиент выводит TXT-запись для создания, затем ожидает нажатия Enter:

```
=== DNS-01 Challenge ===
Create a DNS TXT record:
  Name:  _acme-challenge.your.domain.com
  Type:  TXT
  Value: <base64url-encoded-sha256>

Press Enter once the record has propagated...
```

#### Hook-скрипт (`--dns-hook`)

Автоматизация создания/удаления DNS-записей с помощью внешнего скрипта:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh your.domain.com
```

Hook-скрипт вызывается дважды для каждой авторизации:

1. **Перед валидацией** с `ACME_ACTION=create` - создание TXT-записи
2. **После валидации** с `ACME_ACTION=cleanup` - удаление TXT-записи

Переменные окружения, передаваемые в hook:

| Переменная | Пример |
|---|---|
| `ACME_ACTION` | `create` или `cleanup` |
| `ACME_DOMAIN` | `your.domain.com` |
| `ACME_TXT_NAME` | `_acme-challenge.your.domain.com` |
| `ACME_TXT_VALUE` | `aB3xY...base64url...` |

Пример hook-скрипта (Cloudflare API):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Uses CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID from environment
API="https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/dns_records"
AUTH="Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"

case "${ACME_ACTION}" in
  create)
    curl -s -X POST "${API}" -H "${AUTH}" -H "Content-Type: application/json" --data '{"type":"TXT","name":"'"${ACME_TXT_NAME}"'","content":"\"'"${ACME_TXT_VALUE}"'\"","ttl":120}'
    ;;
  cleanup)
    RECORD_ID=$(curl -s "${API}?type=TXT&name=${ACME_TXT_NAME}" -H "${AUTH}" | jq -r '.result[0].id')
    if [ "${RECORD_ID}" != "null" ]; then
      curl -s -X DELETE "${API}/${RECORD_ID}" -H "${AUTH}"
    fi
    ;;
esac
```

#### Автопроверка распространения (`--dns-wait`)

Опрос DNS до появления TXT-записи (или до таймаута):

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 your.domain.com
```

`--dns-wait <СЕКУНДЫ>` опрашивает каждые 5 секунд с помощью `dig` (с fallback на `nslookup` в Windows) до появления TXT-записи или истечения таймаута.

Можно комбинировать с `--dns-hook` (полная автоматизация) или использовать отдельно (выводит инструкции, затем ожидает автоматически вместо ручного подтверждения).

### Вызов TLS-ALPN-01 (интерактивный)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type tls-alpn-01 your.domain.com
```

Клиент выводит значение расширения `acmeIdentifier`. Необходимо настроить TLS-сервер на порту 443 с самоподписанным сертификатом, содержащим это расширение, перед нажатием Enter.

### Вызов DNS-PERSIST-01 (draft-ietf-acme-dns-persist)

DNS-PERSIST-01 использует постоянную DNS TXT-запись по адресу `_validation-persist.<domain>` для подтверждения контроля над доменом. В отличие от DNS-01, запись не меняется между выпусками - после создания она может быть повторно использована для будущих продлений сертификата без изменений.

Запись привязывает домен к вашему ACME-аккаунту и конкретному CA (идентифицируемому по доменному имени издателя).

#### Интерактивный (по умолчанию)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 your.domain.com
```

Клиент выводит TXT-запись для создания, затем ожидает нажатия Enter:

```
=== DNS-PERSIST-01 Challenge ===
Create a DNS TXT record:
  Name:  _validation-persist.your.domain.com
  Type:  TXT
  Value: letsencrypt.org; accounturi=https://acme-server/acme/acct/123

This record is persistent - it can be reused for future issuances.
Unlike dns-01, it does not need to change per issuance.

Press Enter once the record has propagated...
```

#### С политикой и persistUntil

Для wildcard-сертификатов используйте `--persist-policy wildcard`. Флаг `--persist-until` задаёт Unix-метку времени, после которой запись считается просроченной:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --persist-policy wildcard --persist-until 1767225600 "*.your.domain.com" your.domain.com
```

Создаётся запись вида:

```
letsencrypt.org; accounturi=https://acme-server/acme/acct/123; policy=wildcard; persistUntil=1767225600
```

#### Hook-скрипт (`--dns-hook`)

Автоматизация создания DNS-записей с помощью внешнего скрипта:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --dns-hook /usr/local/bin/dns-hook.sh your.domain.com
```

Hook вызывается с `ACME_ACTION=create` перед валидацией и `ACME_ACTION=cleanup` после:

| Переменная | Пример |
|---|---|
| `ACME_ACTION` | `create` or `cleanup` |
| `ACME_DOMAIN` | `your.domain.com` |
| `ACME_TXT_NAME` | `_validation-persist.your.domain.com` |
| `ACME_TXT_VALUE` | `letsencrypt.org; accounturi=https://...` |

#### Автопроверка появления TXT-записи (`--dns-wait`)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type dns-persist-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 your.domain.com
```

#### Просмотр инструкций по настройке записи

Субкоманда `show-dns-persist01` выводит запись, которую нужно создать, без запуска полного ACME-процесса:

```sh
acme-client-rs --directory https://your-acme-server/directory show-dns-persist01 --domain your.domain.com --issuer-domain-name letsencrypt.org
```

С JSON-выводом:

```sh
acme-client-rs --directory https://your-acme-server/directory --output-format json show-dns-persist01 --domain your.domain.com --issuer-domain-name letsencrypt.org --persist-policy wildcard --persist-until 1767225600
```

> **Примечание:** DNS-PERSIST-01 определён в [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/html/draft-sheurich-acme-dns-persist). Pebble уже поддерживает его. Поддержка Let's Encrypt staging ожидается в конце Q1 2026, production - в Q2 2026.

### Использование --challenge-dir (интеграция с reverse proxy)

Если у вас уже есть веб-сервер (nginx, Apache и т.д.), обслуживающий порт 80, используйте `--challenge-dir` для записи файла вызова в директорию, которую он обслуживает:

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 --challenge-dir /var/www/html your.domain.com
```

Клиент записывает файл токена в `/var/www/html/.well-known/acme-challenge/<token>` и удаляет его после валидации.

### IP-идентификаторы (RFC 8738)

IP-адреса определяются автоматически - просто передайте их как позиционные аргументы:

```sh
# IPv4
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 192.0.2.1

# IPv6 (в скобках или без)
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 [2001:db8::1]
```

> **Примечание:** Вызовы DNS-01 и DNS-PERSIST-01 не поддерживаются для IP-идентификаторов. Используйте HTTP-01 или TLS-ALPN-01.

### Мультидоменные сертификаты (Multi-SAN)

```sh
acme-client-rs --directory https://your-acme-server/directory run --contact you@example.com --challenge-type http-01 example.com www.example.com api.example.com
```

<details>
<summary><h2>Сборка</h2></summary>

### Стандартная release-сборка

```sh
cargo build --release
```

Бинарный файл находится в `target/release/acme-client-rs` (или `.exe` на Windows).

### Минимальный защищённый бинарник

Профиль `release` в `Cargo.toml` уже настроен на минимальный размер и отсутствие отладочной информации:

```toml
[profile.release]
opt-level = "z"        # Optimize for size (not speed)
lto = true             # Full link-time optimization - eliminates dead code across crates
codegen-units = 1      # Single codegen unit - maximum optimization
panic = "abort"        # No unwind tables - saves ~100-200 KB
strip = true           # Strip all symbols and DWARF debug info
```

Сборка со всеми флагами безопасности:

#### Windows (MSVC)

```powershell
$env:RUSTFLAGS = "-C control-flow-guard=yes -C link-args=/DYNAMICBASE -C link-args=/HIGHENTROPYVA -C link-args=/NXCOMPAT -C link-args=/CETCOMPAT"
cargo build --release
```

| Флаг | Эффект |
|---|---|
| `control-flow-guard=yes` | Включает Control Flow Guard (CFG) - предотвращает перехват целей вызовов |
| `/DYNAMICBASE` | ASLR - рандомизация базового адреса при загрузке (включено по умолчанию, указано явно для ясности) |
| `/HIGHENTROPYVA` | 64-битный ASLR с высокой энтропией - использует полное адресное пространство |
| `/NXCOMPAT` | DEP/NX - помечает стек и кучу как неисполняемые |
| `/CETCOMPAT` | Intel CET shadow stack - аппаратная защита адреса возврата |

#### Linux (GNU/musl)

**Предварительные требования:** Крейт `native-tls` использует OpenSSL на Linux. Сначала установите заголовочные файлы:

| Дистрибутив | Команда установки |
|---|---|
| Debian / Ubuntu | `sudo apt install pkg-config libssl-dev` |
| RHEL / Fedora | `sudo dnf install pkg-config openssl-devel` |
| Alpine (musl) | `apk add pkgconf openssl-dev openssl-libs-static` |
| Arch | `sudo pacman -S pkg-config openssl` |

```sh
RUSTFLAGS="-C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" cargo build --release
```

Для полностью статического бинарника (без зависимости от glibc):

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack" cargo build --release --target x86_64-unknown-linux-musl
```

| Флаг | Эффект |
|---|---|
| `relocation-model=pie` | Position-Independent Executable - включает ASLR |
| `-z relro` | Read-only relocations - GOT доступна только для чтения после запуска |
| `-z now` | Full RELRO - разрешение всех символов при загрузке (без ленивой загрузки) |
| `-z noexecstack` | Неисполняемый стек (NX) |
| `target-feature=+crt-static` | Статическая линковка C-рантайма (с musl) |

#### macOS

```sh
RUSTFLAGS="-C relocation-model=pie" cargo build --release
```

macOS включает большинство защит по умолчанию (ASLR, NX stack, code signing).

### Проверка свойств безопасности

#### Windows

```powershell
# Check binary flags with dumpbin (from VS Developer Command Prompt)
dumpbin /headers target\release\acme-client-rs.exe | Select-String "DLL characteristics"
# Should show: Dynamic base, NX compatible, High Entropy VA, Guard CF, CET Compatible
```

#### Linux

```sh
# checksec (from pwntools or checksec.sh)
checksec --file=target/release/acme-client-rs
# Expected: RELRO=Full, Stack Canary=yes, NX=yes, PIE=yes

# Or manually
readelf -l target/release/acme-client-rs | grep -i "gnu_relro\|gnu_stack"
file target/release/acme-client-rs  # should say "ELF 64-bit ... dynamically linked" or "statically linked"
```

### Сборка с Podman (или Docker)

Можно собрать полностью статический бинарник для Linux внутри контейнера - локальный Rust-тулчейн или заголовки OpenSSL не нужны.

Пример ниже использует многоэтапную сборку: первый этап компилирует против musl с вендоренным OpenSSL 3.5.x, второй этап извлекает бинарник.

Создайте `Containerfile` (работает как с `podman`, так и с `docker`):

```dockerfile
# -- Stage 1: Build --
FROM docker.io/library/rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconf openssl-dev openssl-libs-static perl make

WORKDIR /src
COPY . .

# Static musl build with full security hardening
ENV OPENSSL_STATIC=1
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie -C link-args=-Wl,-z,relro,-z,now,-z,noexecstack"

RUN cargo build --release && strip target/release/acme-client-rs

# -- Stage 2: Minimal runtime image --
FROM docker.io/library/alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /src/target/release/acme-client-rs /usr/local/bin/acme-client-rs

ENTRYPOINT ["acme-client-rs"]
```

Сборка и извлечение бинарника:

```sh
# Build the image
podman build -t acme-client-rs .

# Copy the static binary out of the image
podman create --name acme-tmp acme-client-rs
podman cp acme-tmp:/usr/local/bin/acme-client-rs ./acme-client-rs
podman rm acme-tmp

# Verify
file ./acme-client-rs
# -> ELF 64-bit LSB pie executable, x86-64, statically linked
./acme-client-rs --help
```

Или запуск непосредственно из контейнера:

```sh
podman run --rm acme-client-rs --help
podman run --rm -v ./certs:/certs:Z acme-client-rs --directory https://acme-server/directory --account-key /certs/account.key run --contact you@example.com your.domain.com
```

> **Примечание:** Пакет `openssl-dev` в Alpine содержит OpenSSL 3.5.x (3.5.5 на момент написания). Переменная окружения `OPENSSL_STATIC=1` указывает скрипту сборки `openssl-sys` линковать OpenSSL статически, создавая полностью самодостаточный бинарник без зависимостей времени выполнения. Базовый образ `rust:alpine` использует musl libc нативно, поэтому кросс-компиляция не требуется.

Для использования Docker вместо Podman просто замените `podman` на `docker` во всех командах выше.

### Сравнение размеров

Типичные размеры бинарника (x86_64, Windows MSVC):

| Профиль | Примерный размер |
|---|---|
| `debug` (по умолчанию) | ~25-30 МБ |
| `release` (до оптимизации) | ~4.8 МБ |
| `release` (opt-level=z, LTO, strip, abort + CFG/ASLR/DEP/CET) | ~2.3 МБ |

</details>

<details>
<summary><h2>Конфигурационный файл</h2></summary>

Все флаги CLI можно задать в TOML-файле конфигурации. Генерация самодокументируемого шаблона конфига:

```sh
acme-client-rs generate-config > acme-client-rs.toml
```

Готовый пример также включён в репозиторий как `acme-client-rs.toml.example`.

Конфигурационный файл опционален. Загружайте его через `--config <PATH>` или переменную `ACME_CONFIG`.

**Приоритет без конфигурационного файла:** флаги CLI > переменные окружения > встроенные значения по умолчанию.
**Приоритет с конфигурационным файлом:** флаги CLI > конфигурационный файл > встроенные значения по умолчанию.

При загрузке конфигурационного файла переменные окружения **игнорируются** -- конфигурационный файл является единственным источником данных. Исключения: `ACME_INSECURE`, пароли ключей (`--key-password-file`) и EAB-учётные данные (`--eab-kid`, `--eab-hmac-key`) по-прежнему читаются из окружения как запасной вариант для секретов, которые не должны храниться в файлах конфигурации.

Поведение загрузки:
- `--config <PATH>` (или переменная `ACME_CONFIG`): загрузка из указанного пути (переменные окружения игнорируются)
- Без конфигурационного файла: флаги CLI и переменные окружения работают как обычно

Пример конфигурации:

```toml
[global]
directory = "https://acme-v02.api.letsencrypt.org/directory"
account_key = "/etc/acme/account.key"

[run]
domains = ["example.com", "www.example.com"]
contact = "admin@example.com"
challenge_type = "http-01"
challenge_dir = "/var/www/acme"
cert_output = "/etc/ssl/certs/example.com.pem"
key_output = "/etc/ssl/private/example.com.key"
days = 30
```

С такой конфигурацией продление сводится к одной команде:

```sh
acme-client-rs --config acme-client-rs.toml run
```

Флаги CLI перекрывают конфигурационный файл, поэтому можно настроить выполнение индивидуально:

```sh
acme-client-rs run --challenge-type dns-01 other.domain.com
```

Для просмотра итоговой объединённой конфигурации и источника каждого значения:

```sh
acme-client-rs show-config --verbose
```

Каждое значение аннотировано источником: `(cli)`, `(env)`, `(config)` или `(default)`.

</details>

<details>
<summary><h2>Как работает ACME</h2></summary>

Протокол ACME (RFC 8555) автоматизирует выпуск сертификатов через процесс вызов-ответ. Вот как каждый шаг соответствует командам `acme-client-rs`:

```
Клиент                                ACME-сервер (напр. Let's Encrypt)
  |                                         |
  |  1. GET /directory                      |
  |  ------------------------------------>  |   Получение списка эндпоинтов
  |  <------------------------------------  |   {newNonce, newAccount, newOrder, ...}
  |                                         |
  |  2. POST /newAccount                    |   -- account --
  |  ------------------------------------>  |   Регистрация или поиск аккаунта
  |  <------------------------------------  |   URL аккаунта + статус
  |                                         |
  |  3. POST /newOrder                      |   -- order --
  |  ------------------------------------>  |   Запрос сертификата для домена(-ов)
  |  <------------------------------------  |   URL заказа + URL авторизаций
  |                                         |
  |  4. POST /authz/{id}                    |   -- get-authz --
  |  ------------------------------------>  |   Получение вызовов для каждого домена
  |  <------------------------------------  |   [http-01, dns-01, dns-persist-01, tls-alpn-01]
  |                                         |
  |  5. Подтверждение владения доменом      |   -- serve-http01 / show-dns01 --
  |     HTTP-01: токен на порту 80          |
  |     DNS-01:  TXT-запись _acme-challenge |
  |     DNS-PERSIST-01: постоянная TXT-зап. |
  |     TLS-ALPN-01: acmeIdentifier в TLS   |
  |                                         |
  |  6. POST /challenge/{id}                |   -- respond-challenge --
  |  ------------------------------------>  |   «Готов, проверяйте»
  |  <------------------------------------  |   Статус вызова: processing/valid
  |                                         |
  |  7. POST /order/{id}/finalize           |   -- finalize --
  |  ------------------------------------>  |   Отправка CSR
  |  <------------------------------------  |   Статус заказа: processing/valid
  |                                         |
  |  8. POST /order/{id}                    |   -- poll-order --
  |  ------------------------------------>  |   Ожидание выпуска
  |  <------------------------------------  |   URL сертификата
  |                                         |
  |  9. POST /certificate/{id}              |   -- download-cert --
  |  ------------------------------------>  |   Загрузка цепочки сертификатов
  |  <------------------------------------  |   PEM (конечный + промежуточные)
  |                                         |
  | 10. POST /revokeCert (опционально)      |   -- revoke-cert --
  |  ------------------------------------>  |   Отзыв сертификата
  |  <------------------------------------  |   200 OK
  |                                         |
  | 11. GET /renewalInfo/{certID} (ARI)     |   -- renewal-info --
  |  ------------------------------------>  |   Запрос сроков обновления (RFC 9702)
  |  <------------------------------------  |   suggestedWindow {start, end}
```

Субкоманда `run` выполняет шаги 1-9 автоматически (и опционально шаг 11 с `--ari`). Отдельные субкоманды позволяют выполнять каждый шаг вручную.

> **Все запросы после шага 1 подписываются с помощью JWS (JSON Web Signature) с использованием ключа аккаунта. Сервер аутентифицирует каждый запрос по отпечатку ключа.**

</details>

<details>
<summary><h2>Практические примеры с Let's Encrypt</h2></summary>

### Выпуск сертификата (HTTP-01, встроенный сервер)

```sh
# Generate an account key
acme-client-rs generate-key --account-key /etc/acme/account.key

# Issue a certificate (the client binds port 80 for validation)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key example.com www.example.com
```

### Выпуск сертификата (HTTP-01, с nginx)

Если nginx уже обслуживает порт 80, используйте `--challenge-dir` для записи файла токена в webroot:

```nginx
# /etc/nginx/snippets/acme-challenge.conf
location /.well-known/acme-challenge/ {
    root /var/www/acme;
    try_files $uri =404;
}
```

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key example.com www.example.com

# Reload nginx to pick up the new cert
sudo systemctl reload nginx
```

### Выпуск wildcard-сертификата (DNS-01 или DNS-PERSIST-01)

Wildcard-сертификаты требуют валидации DNS-01 или DNS-PERSIST-01.

**Интерактивный режим** (ручное создание DNS-записи):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-01 --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

**Автоматический режим** (с hook-скриптом и проверкой распространения):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-01 --dns-hook /usr/local/bin/dns-hook.sh --dns-wait 120 --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

**DNS-PERSIST-01** (постоянная запись - изменения при каждом выпуске не нужны):

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type dns-persist-01 --persist-policy wildcard --cert-output /etc/ssl/certs/wildcard.example.com.pem --key-output /etc/ssl/private/wildcard.example.com.key "*.example.com" example.com
```

### Отзыв сертификата

```sh
# Revoke (no reason code)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key revoke-cert /etc/ssl/certs/example.com.pem

# Revoke with reason code (4 = superseded)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key revoke-cert /etc/ssl/certs/example.com.pem --reason 4
```

Коды причин (RFC 5280 Section 5.3.1):

| Код | Причина |
|------|--------|
| 0 | Не указана |
| 1 | Компрометация ключа |
| 3 | Изменение принадлежности |
| 4 | Заменён |
| 5 | Прекращение деятельности |

<details>
<summary><strong>Пошаговый ручной процесс (Let's Encrypt)</strong></summary>

```sh
export ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
export ACME_ACCOUNT_KEY_FILE=/etc/acme/account.key

# 1. Register account
acme-client-rs account --contact admin@example.com
# Output: Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456789

export ACME_ACCOUNT_URL=https://acme-v02.api.letsencrypt.org/acme/acct/123456789

# 2. Place order
acme-client-rs order example.com www.example.com
# Output: Order URL, authorization URLs, finalize URL

# 3. Check each authorization
acme-client-rs get-authz https://acme-v02.api.letsencrypt.org/acme/authz/abc123
# Output: challenge type, token, URL

# 4. Serve the challenge (standalone, port 80)
acme-client-rs serve-http01 --token <token> --port 80 &

# 5. Tell the server to validate
acme-client-rs respond-challenge https://acme-v02.api.letsencrypt.org/acme/chall/xyz789

# 6. Finalize with CSR
acme-client-rs finalize --finalize-url https://acme-v02.api.letsencrypt.org/acme/order/123/finalize example.com www.example.com

# 7. Poll until certificate is ready
acme-client-rs poll-order https://acme-v02.api.letsencrypt.org/acme/order/123

# 8. Download the certificate
acme-client-rs download-cert https://acme-v02.api.letsencrypt.org/acme/cert/abc123 --output /etc/ssl/certs/example.com.pem
```

</details>

</details>

<details>
<summary><h2>Автоматизация</h2></summary>

> **Отдельная команда `renew` не нужна.** Субкоманда `run` выполняет роль команды продления при добавлении `--days N`. Она читает сертификат из `--cert-output`, проверяет количество оставшихся дней и обращается к CA только если продление необходимо. Код возврата 0 как при продлении, так и при пропуске.

### Простое продление (с помощью встроенного `--days`)

Флаг `--days` делает `run` идемпотентной - выпуск пропускается, если у существующего сертификата осталось более N дней:

```sh
# Renew only if less than 30 days remain (exits 0 either way)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --days 30 example.com www.example.com && sudo systemctl reload nginx
```

Добавьте в cron для полностью автоматического продления:

```cron
0 3 * * * root acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --days 30 example.com && systemctl reload nginx >> /var/log/acme-renew.log 2>&1
```

### Серверное управление продлением с ARI (RFC 9702)

ACME Renewal Information (ARI) позволяет CA сообщать клиенту, когда продлевать. Вместо фиксированного порога `--days` сервер предоставляет рекомендуемое временное окно на основе срока действия сертификата, событий отзыва или изменений политики.

**Запрос окна продления:**

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key renewal-info /etc/ssl/certs/example.com.pem
```

Вывод:

```
CertID:   <base64url(AKI)>.<base64url(Serial)>
Suggested renewal window:
  Start:  2026-04-01T00:00:00Z
  End:    2026-04-15T00:00:00Z
Status:   not yet due (20 days until window opens)
```

**Использование ARI в автоматическом продлении:**

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --ari example.com www.example.com && sudo systemctl reload nginx
```

Как работает `--ari`:

1. Разбирает существующий сертификат из `--cert-output`
2. Запрашивает эндпоинт `renewalInfo` CA с AKI и серийным номером сертификата
3. Если текущее время до начала рекомендуемого окна - пропускает продление
4. Если в пределах окна (или после него) - выполняет продление и включает поле `replaces` в заказ, позволяя CA связать новый сертификат со старым
5. Если ARI недоступна (сервер не поддерживает или запрос не удался) - переходит на порог `--days`

Комбинируйте `--ari` и `--days` для эшелонированной защиты:

```sh
# ARI decides timing when available; --days is the safety net
acme-client-rs run --ari --days 30 --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --contact admin@example.com example.com
```

**Рекомендуемая схема:** настройте ежедневное задание cron (или таймер systemd), запускающее полную команду `run` с `--ari --days 30`. В большинстве случаев клиент завершится немедленно ("окно продления ещё не открыто"). Когда рекомендуемое CA окно откроется, продление произойдёт автоматически. Если ARI недоступна, `--days 30` выступает страховкой:

```cron
# /etc/cron.d/acme-ari-renew
0 3 * * * root /usr/local/bin/acme-client-rs \
  --directory https://acme-v02.api.letsencrypt.org/directory \
  --account-key /etc/acme/account.key \
  run --ari --days 30 \
  --contact admin@example.com \
  --challenge-type http-01 --challenge-dir /var/www/acme \
  --cert-output /etc/ssl/certs/example.com.pem \
  --key-output /etc/ssl/private/example.com.key \
  example.com www.example.com \
  && systemctl reload nginx >> /var/log/acme-renew.log 2>&1
```

Ключевое преимущество: CA контролирует *время* продления (через рекомендуемое окно), что помогает распределить нагрузку на продление и позволяет CA сигнализировать о досрочном продлении при событиях отзыва или изменении политики.

> **Примечание:** ARI требует, чтобы CA публиковал URL `renewalInfo` в своей директории. Let's Encrypt поддерживает ARI. Если сервер не поддерживает ARI, `--ari` молча переходит на `--days`.

### Защита от несовпадения доменов

При использовании `--ari` или `--days` инструмент сравнивает запрашиваемый список доменов с SAN (Subject Alternative Names) существующего сертификата. Если домены отличаются, инструмент рассматривает это как **перевыпуск** (не продление) и действует следующим образом:

**Без `--reissue-on-mismatch`** (безопасное поведение по умолчанию): фиксирует несовпадение и пропускает — существующий сертификат никогда не перезаписывается. Это защищает рабочие сертификаты от случайного изменения доменов:

```
$ acme-client-rs run --days 30 --cert-output cert.pem example.com api.example.com
Domain mismatch: cert has [example.com, www.example.com], requested [api.example.com, example.com] (added: [api.example.com], removed: [www.example.com]). Use --reissue-on-mismatch to override.
```

**С `--reissue-on-mismatch`**: подтверждает несовпадение и выпускает новый сертификат с обновлённым списком доменов, минуя проверки ARI/days. Старый сертификат перезаписывается:

```sh
acme-client-rs run --days 30 --reissue-on-mismatch --cert-output cert.pem --key-output key.pem example.com api.example.com
```

Сравнение нечувствительно к регистру и нормализует IP-адреса (IPv4 и IPv6). Если существующий сертификат не удаётся разобрать, проверка несовпадения пропускается и проверки ARI/days выполняются в обычном режиме (отказоустойчиво).

> **Примечание:** Когда `--reissue-on-mismatch` вызывает перевыпуск, `ari_cert_id` НЕ устанавливается — это новый заказ, а не `replaceOrder` (RFC 9702), поскольку заменяемый сертификат содержит другие идентификаторы.

### Bash-скрипт: выпуск и продление

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-renew.sh
# Issue or renew a certificate, then reload the web server.
set -euo pipefail

DOMAIN="example.com"
ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CERT="/etc/ssl/certs/${DOMAIN}.pem"
KEY="/etc/ssl/private/${DOMAIN}.key"
CONTACT="admin@${DOMAIN}"
WEBROOT="/var/www/acme"
RENEW_DAYS=30

# Check if certificate exists and is not expiring soon
if [ -f "${CERT}" ]; then
    EXPIRY=$(openssl x509 -enddate -noout -in "${CERT}" | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "${EXPIRY}" +%s)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    if [ "${DAYS_LEFT}" -gt "${RENEW_DAYS}" ]; then
        echo "Certificate valid for ${DAYS_LEFT} days, skipping renewal"
        exit 0
    fi
    echo "Certificate expires in ${DAYS_LEFT} days, renewing..."
fi

# Generate account key if it doesn't exist
if [ ! -f "${ACCOUNT_KEY}" ]; then
    acme-client-rs generate-key --account-key "${ACCOUNT_KEY}"
fi

# Issue/renew the certificate
acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "${CONTACT}" --challenge-type http-01 --challenge-dir "${WEBROOT}" --cert-output "${CERT}" --key-output "${KEY}" "${DOMAIN}" "www.${DOMAIN}"

# Reload web server
sudo systemctl reload nginx

echo "Certificate renewed successfully"
```

```sh
chmod +x /usr/local/bin/acme-renew.sh
```

### Задание Cron: ежедневная проверка продления

```cron
# /etc/cron.d/acme-renew
# Check daily at 3:00 AM, renew if within 30 days of expiry
0 3 * * * root /usr/local/bin/acme-renew.sh >> /var/log/acme-renew.log 2>&1
```

### Таймер systemd: запланированное продление

```ini
# /etc/systemd/system/acme-renew.service
[Unit]
Description=ACME certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/acme-renew.sh
StandardOutput=journal
StandardError=journal
# Security hardening
ProtectSystem=strict
ReadWritePaths=/etc/ssl/certs /etc/ssl/private /etc/acme /var/www/acme
PrivateTmp=true
NoNewPrivileges=true
```

```ini
# /etc/systemd/system/acme-renew.timer
[Unit]
Description=Run ACME renewal twice daily

[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now acme-renew.timer

# Check timer status
systemctl list-timers acme-renew.timer
# Check logs
journalctl -u acme-renew.service
```

### Скрипт продления для нескольких доменов

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-renew-all.sh
# Renew certificates for multiple domains from a config list.
set -euo pipefail

ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CONTACT="admin@example.com"
WEBROOT="/var/www/acme"
RENEW_DAYS=30

# Domain list: one primary domain per line, SANs space-separated
DOMAINS_FILE="/etc/acme/domains.txt"
# Example /etc/acme/domains.txt:
#   example.com www.example.com
#   api.example.com
#   *.internal.example.com internal.example.com

RENEWED=0

while IFS= read -r line; do
    [ -z "${line}" ] && continue
    [[ "${line}" =~ ^# ]] && continue

    # First domain is the primary (used for filenames)
    PRIMARY=$(echo "${line}" | awk '{print $1}' | tr -d '*.')
    CERT="/etc/ssl/certs/${PRIMARY}.pem"
    KEY="/etc/ssl/private/${PRIMARY}.key"

    # Check expiry
    if [ -f "${CERT}" ]; then
        DAYS_LEFT=$(( ( $(date -d "$(openssl x509 -enddate -noout -in "${CERT}" | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
        if [ "${DAYS_LEFT}" -gt "${RENEW_DAYS}" ]; then
            echo "[SKIP] ${PRIMARY}: ${DAYS_LEFT} days remaining"
            continue
        fi
        echo "[RENEW] ${PRIMARY}: ${DAYS_LEFT} days remaining"
    else
        echo "[NEW] ${PRIMARY}: no certificate found"
    fi

    # Determine challenge type (wildcard requires dns-01)
    CHALLENGE="http-01"
    EXTRA_ARGS=(--challenge-dir "${WEBROOT}")
    if echo "${line}" | grep -q '\*'; then
        CHALLENGE="dns-01"
        EXTRA_ARGS=()
    fi

    # shellcheck disable=SC2086
    acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "${CONTACT}" --challenge-type "${CHALLENGE}" "${EXTRA_ARGS[@]}" --cert-output "${CERT}" --key-output "${KEY}" ${line}

    RENEWED=$((RENEWED + 1))
done < "${DOMAINS_FILE}"

if [ "${RENEWED}" -gt 0 ]; then
    echo "Renewed ${RENEWED} certificate(s), reloading nginx"
    sudo systemctl reload nginx
fi
```

### Событийная модель: использование встроенных hook-скриптов

Флаги `--on-challenge-ready` и `--on-cert-issued` позволяют запускать скрипты в ключевые моменты ACME-процесса без написания обёртки:

```sh
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key /etc/acme/account.key run --contact admin@example.com --challenge-type http-01 --challenge-dir /var/www/acme --cert-output /etc/ssl/certs/example.com.pem --key-output /etc/ssl/private/example.com.key --on-cert-issued /usr/local/bin/deploy-cert.sh example.com www.example.com
```

Пример `deploy-cert.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# ACME_DOMAINS, ACME_CERT_PATH, ACME_KEY_PATH, ACME_KEY_ENCRYPTED set by acme-client-rs
echo "Certificate issued for: ${ACME_DOMAINS}"
cp "${ACME_CERT_PATH}" /opt/myapp/tls/cert.pem
cp "${ACME_KEY_PATH}" /opt/myapp/tls/key.pem
chown myapp:myapp /opt/myapp/tls/*.pem
sudo systemctl reload nginx
sudo systemctl restart myapp
```

Пример `on-challenge-ready.sh` (для логирования или уведомлений):

```bash
#!/usr/bin/env bash
set -euo pipefail
# ACME_DOMAIN, ACME_CHALLENGE_TYPE, ACME_TOKEN (dns-01/tls-alpn-01),
# ACME_KEY_AUTH (dns-01/tls-alpn-01), ACME_TXT_NAME (dns-01/dns-persist-01),
# ACME_TXT_VALUE (dns-01/dns-persist-01) set by acme-client-rs
echo "Challenge ready: ${ACME_CHALLENGE_TYPE} for ${ACME_DOMAIN}"
```

### Событийная модель: скрипт-обёртка с хуками

Для более сложной логики до/после выполнения (например, остановка сервисов перед привязкой порта 80) скрипт-обёртка даёт полный контроль:

```bash
#!/usr/bin/env bash
# /usr/local/bin/acme-with-hooks.sh
# Certificate issuance with pre/post hooks for service management.
set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain>}"
ACME_DIR="https://acme-v02.api.letsencrypt.org/directory"
ACCOUNT_KEY="/etc/acme/account.key"
CERT="/etc/ssl/certs/${DOMAIN}.pem"
KEY="/etc/ssl/private/${DOMAIN}.key"

# -- Pre-hook: stop conflicting services before port 80 bind --
pre_hook() {
    echo "Stopping nginx to free port 80..."
    sudo systemctl stop nginx
}

# -- Post-hook: deploy cert and restart services --
post_hook() {
    echo "Deploying certificate..."
    # Copy to application-specific locations if needed
    cp "${CERT}" /opt/myapp/tls/cert.pem
    cp "${KEY}" /opt/myapp/tls/key.pem
    chown myapp:myapp /opt/myapp/tls/*.pem

    echo "Starting nginx..."
    sudo systemctl start nginx

    echo "Restarting application..."
    sudo systemctl restart myapp
}

# -- Cleanup on failure --
cleanup() {
    echo "Ensuring nginx is running..."
    sudo systemctl start nginx || true
}
trap cleanup ERR

pre_hook

acme-client-rs --directory "${ACME_DIR}" --account-key "${ACCOUNT_KEY}" run --contact "admin@${DOMAIN}" --challenge-type http-01 --cert-output "${CERT}" --key-output "${KEY}" "${DOMAIN}"

post_hook

echo "Done: certificate issued and deployed for ${DOMAIN}"
```

### PowerShell: запланированная задача Windows

```powershell
# acme-renew.ps1
$domain   = "example.com"
$acmeDir  = "https://acme-v02.api.letsencrypt.org/directory"
$acmeKey  = "C:\ProgramData\acme\account.key"
$certPath = "C:\ProgramData\acme\certs\$domain.pem"
$keyPath  = "C:\ProgramData\acme\certs\$domain.key"
$contact  = "admin@$domain"

# Check if renewal is needed
if (Test-Path $certPath) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days
    if ($daysLeft -gt 30) {
        Write-Host "Certificate valid for $daysLeft days, skipping"
        exit 0
    }
    Write-Host "Certificate expires in $daysLeft days, renewing..."
}

# Run the ACME flow
& acme-client-rs.exe `
  --directory $acmeDir `
  --account-key $acmeKey `
  run `
  --contact $contact `
  --challenge-type http-01 `
  --cert-output $certPath `
  --key-output $keyPath `
  $domain

if ($LASTEXITCODE -ne 0) { throw "ACME renewal failed" }

# Import into Windows certificate store (optional)
$pfxPath = "C:\ProgramData\acme\certs\$domain.pfx"
openssl pkcs12 -export -out $pfxPath -inkey $keyPath -in $certPath -passout pass:
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My

Write-Host "Certificate renewed and imported"
```

Регистрация как запланированная задача:

```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-ExecutionPolicy Bypass -File C:\ProgramData\acme\acme-renew.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"
Register-ScheduledTask -TaskName "ACME Certificate Renewal" `
  -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest
```

</details>

<details>
<summary><h2>Тестирование с Pebble</h2></summary>

[Pebble](https://github.com/letsencrypt/pebble) - миниатюрный тестовый ACME-сервер от Let's Encrypt. Это самый простой способ тестирования ACME-процессов локально.

### 1. Запуск Pebble с Docker Compose

Создайте `docker-compose.yml` (или используйте из репозитория Pebble):

```yaml
version: "3"
services:
  pebble:
    image: letsencrypt/pebble:latest
    command: pebble -config /test/config/pebble-config.json -strict
    ports:
      - "14000:14000"  # ACME server
      - "15000:15000"  # Management interface
    environment:
      - PEBBLE_VA_NOSLEEP=1           # Speed up validation (no delay)
      - PEBBLE_VA_ALWAYS_VALID=1      # Accept any challenge without checking (for local testing)
      - PEBBLE_WFE_NONCEREJECT=0      # Don't randomly reject nonces

  challtestsrv:
    image: letsencrypt/pebble-challtestsrv:latest
    command: pebble-challtestsrv -defaultIPv4 host.docker.internal
    ports:
      - "8055:8055"   # Challenge test server management
```

Запуск:

```sh
docker compose up -d
```

> **Примечание:** `PEBBLE_VA_ALWAYS_VALID=1` заставляет Pebble принимать все вызовы без реальной проверки. Идеально для локального тестирования, когда сервер валидации не может достичь вашу машину. Уберите этот флаг, если хотите тестировать реальную валидацию вызовов.

### 2. Генерация ключа аккаунта

```sh
acme-client-rs generate-key --account-key account.key
```

### 3. Тестирование полного процесса (автоматический режим)

`--directory` по умолчанию указывает на `https://localhost:14000/dir` (стандартный URL Pebble), поэтому флаг `--directory` не нужен:

```sh
acme-client-rs run --contact test@example.com --challenge-type http-01 --http-port 5002 test.example.com
```

> **Замечание о TLS:** Pebble использует самоподписанный сертификат. Используйте флаг `--insecure` (или `ACME_INSECURE=true`) для отключения проверки TLS при тестировании с Pebble.

### 4. Пошаговое тестирование (ручной процесс)

Пошаговое прохождение каждого шага протокола ACME:

```sh
# Set variables for convenience
export ACME_DIRECTORY_URL=https://localhost:14000/dir
export ACME_ACCOUNT_KEY_FILE=account.key

# a) Create an account
acme-client-rs account --contact test@example.com
# -> Note the Account URL printed

# b) Place an order
export ACME_ACCOUNT_URL=<account-url-from-above>
acme-client-rs order test.example.com
# -> Note the authz URL(s) and finalize URL

# c) Check authorization details
acme-client-rs get-authz <authz-url>
# -> Note the challenge URL and token for your chosen type

# d) (HTTP-01) Start the challenge server in one terminal
acme-client-rs serve-http01 --token <token> --port 5002

# e) In another terminal, tell the CA the challenge is ready
acme-client-rs respond-challenge <challenge-url>

# f) Finalize the order with a CSR
acme-client-rs finalize --finalize-url <finalize-url> test.example.com

# g) Poll until the certificate is ready
acme-client-rs poll-order <order-url>

# h) Download the certificate
acme-client-rs download-cert <certificate-url> --output cert.pem

# i) (Optional) Revoke the certificate
acme-client-rs revoke-cert cert.pem

# j) (Optional) Deactivate the account
acme-client-rs deactivate-account
```

### 5. Тестирование без Docker

Можно запустить Pebble напрямую, если установлен Go:

```sh
git clone https://github.com/letsencrypt/pebble.git
cd pebble
go install ./cmd/pebble
PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json
```

### Устранение неполадок Pebble

| Проблема | Решение |
|---|---|
| Ошибка TLS handshake при подключении к Pebble | Используйте `--insecure` (или `ACME_INSECURE=true`) для отключения проверки TLS. Альтернативно установите `SSL_CERT_FILE` на файл `test/certs/pebble.minica.pem` из Pebble |
| Ошибка валидации вызова | Установите `PEBBLE_VA_ALWAYS_VALID=1` или убедитесь, что ваш сервер вызовов доступен из контейнера Pebble |
| Ошибки `badNonce` | Это нормально - клиент автоматически повторяет попытку. Установите `PEBBLE_WFE_NONCEREJECT=0` для отключения случайного отклонения nonce |
| Порт 14000 уже используется | Остановите существующий экземпляр Pebble: `docker compose down` |

</details>

## Справочник CLI

### Глобальные опции

| Опция | Сокращение | Переменная окружения | По умолчанию | Описание |
|---|---|---|---|---|
| `--config <PATH>` | | `ACME_CONFIG` | - | Путь к TOML-файлу конфигурации (при загрузке переменные окружения игнорируются, кроме секретов) |
| `--directory <URL>` | `-d` | `ACME_DIRECTORY_URL` | `https://localhost:14000/dir` | URL директории ACME-сервера |
| `--account-key <PATH>` | `-k` | `ACME_ACCOUNT_KEY_FILE` | `account.key` | Путь к ключу аккаунта (PKCS#8 PEM) |
| `--account-url <URL>` | `-a` | `ACME_ACCOUNT_URL` | - | URL аккаунта (требуется после создания аккаунта) |
| `--output-format <FMT>` | | `ACME_OUTPUT_FORMAT` | `text` | Формат вывода: `text` (для человека) или `json` (структурированный) |
| `--insecure` | | `ACME_INSECURE` | `false` | Отключить проверку TLS-сертификата (для тестирования с самоподписанными CA, такими как Pebble) |

Глобальные опции можно указывать до или после субкоманды.

### Субкоманды

| Команда | Описание |
|---|---|
| `generate-config` | Генерация самодокументирующегося шаблона TOML-конфигурации |
| `show-config` | Показать итоговую объединённую конфигурацию (с `--verbose` - источники значений) |
| `generate-key` | Генерация новой пары ключей аккаунта (ES256, ES384, ES512, RSA-2048, RSA-4096, Ed25519) |
| `account` | Создание или поиск ACME-аккаунта |
| `order <domains...>` | Создание нового заказа на сертификат |
| `get-authz <url>` | Получение объекта авторизации |
| `respond-challenge <url>` | Сообщить серверу, что вызов готов |
| `serve-http01` | Обслуживание ответа на вызов HTTP-01 |
| `show-dns01` | Показать инструкции по настройке TXT-записи DNS-01 |
| `show-dns-persist01` | Показать инструкции по настройке постоянной TXT-записи DNS-PERSIST-01 |
| `finalize` | Финализация заказа с новым CSR |
| `poll-order <url>` | Опрос текущего статуса заказа |
| `download-cert <url>` | Загрузка выпущенного сертификата |
| `deactivate-account` | Деактивация текущего аккаунта |
| `key-rollover` | Ротация ключа аккаунта (RFC 8555 Section 7.3.5) |
| `pre-authorize` | Предварительная авторизация идентификатора перед созданием заказа (RFC 8555 Section 7.4.1) |
| `renewal-info <path>` | Запрос ACME Renewal Information для сертификата (RFC 9702) |
| `revoke-cert <path>` | Отзыв сертификата |
| `run <domains...>` | Запуск полного ACME-процесса от начала до конца |

### Опции `run`

| Опция | По умолчанию | Описание |
|---|---|---|
| `--contact <EMAIL>` | - | Email для контакта ACME-аккаунта |
| `--challenge-type <TYPE>` | `http-01` | Тип вызова: `http-01`, `dns-01`, `dns-persist-01` или `tls-alpn-01` |
| `--http-port <PORT>` | `80` | Порт встроенного HTTP-01 сервера (автономный режим) |
| `--challenge-dir <PATH>` | - | Записывать файлы HTTP-01 вызовов сюда вместо запуска сервера |
| `--dns-hook <SCRIPT>` | - | Путь к hook-скрипту DNS-01 (вызывается с `ACME_ACTION=create\|cleanup`) |
| `--dns-wait <SECONDS>` | - | Ждать до N секунд распространения DNS TXT (опрос каждые 5 с) |
| `--dns-propagation-concurrency <N>` | `5` | Максимум параллельных проверок распространения DNS при использовании `--dns-hook` с несколькими доменами |
| `--challenge-timeout <SECONDS>` | `300` | Максимум секунд ожидания валидации challenge после отправки ответа (опрос каждые 2 с) |
| `--cert-output <PATH>` | `certificate.pem` | Сохранить сертификат в этот файл |
| `--key-output <PATH>` | `private.key` | Сохранить закрытый ключ в этот файл |
| `--days <N>` | - | **Режим продления:** пропустить выпуск, если у существующего `--cert-output` осталось более N дней. Используйте для идемпотентности `run` в cron/планировщике. |
| `--key-password <PW>` | - | Зашифровать закрытый ключ (PKCS#8, AES-256-CBC + scrypt KDF) |
| `--key-password-file <PATH>` | - | Прочитать пароль шифрования ключа из файла (первая строка) |
| `--on-challenge-ready <SCRIPT>` | - | Запустить скрипт после готовности каждого вызова к валидации (dns-01, dns-persist-01, tls-alpn-01; не вызывается для http-01) |
| `--on-cert-issued <SCRIPT>` | - | Запустить скрипт после выпуска и сохранения сертификата на диск |
| `--eab-kid <KID>` | - | EAB Key ID от CA (для CA, требующих привязку внешнего аккаунта) |
| `--eab-hmac-key <KEY>` | - | EAB HMAC-ключ (в кодировке base64url, от CA) |
| `--pre-authorize` | `false` | Предварительная авторизация идентификаторов через newAuthz перед созданием заказа (RFC 8555 Section 7.4.1) |
| `--persist-policy <POLICY>` | - | Политика для записей dns-persist-01 (например, `wildcard` для области wildcard + поддомены) |
| `--persist-until <TIMESTAMP>` | - | Unix-метка времени для параметра `persistUntil` в dns-persist-01 |
| `--cert-key-algorithm <ALG>` | `ec-p256` | Алгоритм ключа сертификата для CSR: `ec-p256`, `ec-p384` или `ed25519` |
| `--ari` | `false` | **Режим продления ARI (RFC 9702):** запрос рекомендуемого окна продления от сервера и пропуск выпуска, если окно ещё не открылось. При продлении поле `replaces` включается в заказ для связывания нового сертификата со старым. Переход на `--days`, если ARI недоступна. |

<details>
<summary><strong>Ротация ключей (RFC 8555 Section 7.3.5)</strong></summary>

Ротация ключа аккаунта без создания нового аккаунта:

```sh
# 1. Generate a new key
acme-client-rs generate-key --account-key new-account.key

# 2. Roll over (old key authenticates, new key proves possession)
acme-client-rs --directory https://acme-v02.api.letsencrypt.org/directory --account-key old-account.key --account-url https://acme-v02.api.letsencrypt.org/acme/acct/123456789 key-rollover --new-key new-account.key

# 3. Use the new key for all future requests
mv new-account.key account.key
```

Старый и новый ключи могут использовать разные алгоритмы (например, переход с RSA-2048 на ES256).

</details>

### Привязка внешнего аккаунта (EAB)

Некоторые CA требуют привязки вашего ACME-аккаунта к существующему внешнему аккаунту. CA предоставляет EAB Key ID и HMAC-ключ при внеполосной регистрации.

```sh
# Register with EAB (account subcommand)
acme-client-rs --directory https://acme-server/directory account --contact admin@example.com --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey

# Full flow with EAB (run subcommand)
acme-client-rs --directory https://acme-server/directory run --contact admin@example.com --challenge-type http-01 --eab-kid my-key-id --eab-hmac-key aBase64urlEncodedHmacKey example.com
```

> **Примечание:** `--eab-kid` и `--eab-hmac-key` должны указываться вместе. HMAC-ключ должен быть в кодировке base64url (как предоставлено CA). EAB нужен только для начальной регистрации аккаунта - последующие запросы используют ключ аккаунта.

### Предварительная авторизация (RFC 8555 Section 7.4.1)

Предварительная авторизация идентификаторов перед созданием заказа (полезно для CA, которые это поддерживают):

```sh
# Pre-authorize a domain (standalone)
acme-client-rs --directory https://acme-server/directory --account-url https://acme-server/acme/acct/123 pre-authorize --domain example.com --challenge-type http-01

# Pre-authorize during the full flow
acme-client-rs --directory https://acme-server/directory run --contact admin@example.com --challenge-type http-01 --pre-authorize example.com
```

> **Примечание:** Не все ACME-серверы поддерживают предварительную авторизацию. Сервер должен публиковать URL `newAuthz` в своей директории.

### Переменные окружения

| Переменная | Описание |
|---|---|
| `ACME_CONFIG` | Путь к файлу конфигурации (альтернатива `--config`) |
| `ACME_DIRECTORY_URL` | URL директории ACME (альтернатива `--directory`) |
| `ACME_ACCOUNT_KEY_FILE` | Путь к ключу аккаунта (альтернатива `--account-key`) |
| `ACME_ACCOUNT_URL` | URL аккаунта (альтернатива `--account-url`) |
| `ACME_OUTPUT_FORMAT` | Формат вывода: `text` или `json` (альтернатива `--output-format`) |
| `ACME_INSECURE` | Отключить проверку TLS-сертификата (альтернатива `--insecure`) |
| `ACME_KEY_PASSWORD_FILE` | Путь к файлу пароля закрытого ключа (альтернатива `--key-password-file`) |
| `ACME_EAB_KID` | EAB Key ID (альтернатива `--eab-kid`) |
| `ACME_EAB_HMAC_KEY` | EAB HMAC-ключ, base64url-кодировка (альтернатива `--eab-hmac-key`) |
| `RUST_LOG` | Фильтр уровня логирования (например, `debug`, `info`, `warn`) |

### Переменные окружения DNS-хука

Устанавливаются клиентом при вызове `--dns-hook`:

| Переменная | Описание |
|---|---|
| `ACME_ACTION` | `create` (перед валидацией) или `cleanup` (после валидации) |
| `ACME_DOMAIN` | Валидируемый домен |
| `ACME_TXT_NAME` | Полное имя DNS-записи (например, `_acme-challenge.example.com` или `_validation-persist.example.com`) |
| `ACME_TXT_VALUE` | Значение TXT-записи (base64url SHA-256 для dns-01 или значение постоянной записи для dns-persist-01) |

### Переменные окружения `--on-challenge-ready`

Устанавливаются при вызове `--on-challenge-ready` (один раз на авторизацию домена):

| Переменная | Описание |
|---|---|
| `ACME_DOMAIN` | Валидируемый домен |
| `ACME_CHALLENGE_TYPE` | Тип вызова (`dns-01`, `dns-persist-01` или `tls-alpn-01`). Не вызывается для `http-01` (обрабатывается автоматически). |
| `ACME_TOKEN` | Токен вызова (только для dns-01 и tls-alpn-01) |
| `ACME_KEY_AUTH` | Полная строка авторизации ключа (`token.thumbprint`; только для dns-01 и tls-alpn-01) |
| `ACME_TXT_NAME` | Имя DNS TXT-записи (только для dns-01 и dns-persist-01) |
| `ACME_TXT_VALUE` | Значение DNS TXT-записи (только для dns-01 и dns-persist-01) |

### Переменные окружения `--on-cert-issued`

Устанавливаются при вызове `--on-cert-issued` (один раз после сохранения сертификата):

| Переменная | Описание |
|---|---|
| `ACME_DOMAINS` | Список доменов в сертификате через запятую |
| `ACME_CERT_PATH` | Путь к сохранённому файлу сертификата |
| `ACME_KEY_PATH` | Путь к сохранённому файлу закрытого ключа |
| `ACME_KEY_ENCRYPTED` | `true` если ключ зашифрован, `false` в противном случае |

## Лицензия

Свободно для использования, модификации и распространения с указанием автора.
