#!/bin/bash
# Запускать на ipa.test.ru, нужен kinit admin заранее
# kinit admin

DOMAIN="test.ru"
COUNT=1000
PASSWORD="P@ssw0rd"

SIMPLE_PASSWORDS=("P@ssw0rd" "Qwerty123" "Password1" "Admin123!" "Welcome1")

echo "Получение cookie-сессии IPA..."

# Получаем сессию через IPA JSON-RPC (не требует kinit для дальнейших вызовов)
IPA_HOST="ipa.test.ru"

# Логинимся и сохраняем cookie
curl -s -c /tmp/ipa_cookie.txt \
    -d "user=admin&password=${PASSWORD}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Referer: https://${IPA_HOST}/ipa" \
    "https://${IPA_HOST}/ipa/session/login_password" \
    --insecure > /dev/null

echo "Cookie получен, начинаем создание пользователей..."

> users_passwords.txt

for i in $(seq 1 $COUNT); do
    USERNAME="testuser$(printf "%04d" $i)"
    PASS_INDEX=$(( i % ${#SIMPLE_PASSWORDS[@]} ))
    PASSWORD="${SIMPLE_PASSWORDS[$PASS_INDEX]}"

    # Создаём пользователя через JSON-RPC
    # userpassword напрямую + ipapwdpolicyviolation не проверяется
    RESPONSE=$(curl -s -b /tmp/ipa_cookie.txt \
        -H "Content-Type: application/json" \
        -H "Referer: https://${IPA_HOST}/ipa" \
        --insecure \
        "https://${IPA_HOST}/ipa/session/json" \
        -d "{
            \"method\": \"user_add\",
            \"params\": [
                [\"${USERNAME}\"],
                {
                    \"givenname\": \"Test\",
                    \"sn\": \"User$(printf "%04d" $i)\",
                    \"userpassword\": \"${PASSWORD}\",
                    \"noprivate\": false
                }
            ],
            \"id\": 0
        }")

    # Сразу снимаем флаг истёкшего пароля через user_mod + krbPasswordExpiration
    # Устанавливаем дату истечения пароля в будущем
    curl -s -b /tmp/ipa_cookie.txt \
        -H "Content-Type: application/json" \
        -H "Referer: https://${IPA_HOST}/ipa" \
        --insecure \
        "https://${IPA_HOST}/ipa/session/json" \
        -d "{
            \"method\": \"user_mod\",
            \"params\": [
                [\"${USERNAME}\"],
                {
                    \"krbpasswordexpiration\": \"20300101000000Z\"
                }
            ],
            \"id\": 0
        }" > /dev/null

    echo "${USERNAME}:${PASSWORD}" >> users_passwords.txt

    if (( i % 50 == 0 )); then
        echo "  создано: $i / $COUNT"
    fi
done

rm -f /tmp/ipa_cookie.txt
echo "Готово. Список -> users_passwords.txt"
