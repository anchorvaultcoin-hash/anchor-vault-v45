# AnchorVaultCoin V45 — инструкции для Claude Code

## Контекст проекта
- **Смарт-контракт:** `src/AnchorVaultV45.sol` — некастодиальное ERC-20 хранилище на Ethereum
- **Сеть:** Sepolia testnet, chainId 11155111
- **Контракт:** `0xAd228aFA6778166003deEBb3Aa8eF9A6Df01399F`
- **Токен ANCR:** `0xf4A1c2D4Fa7D1161bF82f455012fCFed4EC1056e`
- **Пульт управления:** `docs/pulse.html` — single-file HTML, ethers.js v6, тёмная тема
- **Creator:** `0x6226828cc3d1B9c5fc1c4d9BE3dF7b03A4A70479`
- **Guardian:** `0xe0DACa428Abc3F1D5BD333C2D1Ca12dd1a36964D`

## Архитектура контракта (знать обязательно)
- EIP-712 авторизация, 2 ключа на сейф: mainAuthKey + recoveryAuthKey
- Уровни: SAFE / VAULT / FORTRESS
- Паника (`panicWithdraw`) — без подписи, 20% комиссия
- Контракт принимает в сейф ТОЛЬКО токены с decimals==18
- globalEmergency — резервный адрес, первичная установка мгновенна, смена через 7 дней
- 9 EIP-712 операций: Withdraw, TransferVault, InitSecureTransfer, SetTimelock, SetVoluntaryLock, RotateAuthKeys, EarlyClose, RecoverToSafe, EmergencyWithdraw

## Структура репозитория
```
docs/          ← pulse.html (пульт управления)
src/           ← AnchorVaultV45.sol (контракт)
script/        ← деплой и утилиты
test/          ← тесты контракта
.github/       ← CI/CD workflows
```

## Правила работы с кодом
- **Язык общения:** русский
- **JS в pulse.html:** после любых правок проверять синтаксис: `node --check docs/pulse.html` (или извлечь script-блок и проверить)
- **Solidity:** компилятор 0.8.20, BUSL-1.1 лицензия
- **Не трогать без явной просьбы:** адреса контракта/токена в коде, ABI, EIP-712 типы T712, логотип (base64 в файле)
- **i18n:** пульт поддерживает RU/EN/ZH через объект I18N — новые строки добавлять туда же на 3 языках
- **Не использовать `const t =`** нигде в JS пульта — это имя занято под функцию перевода `t(key)`

## Git
- Коммиты на английском, кратко (например: `fix: deadline sync in signOp`)
- Основная ветка: `main`
- Перед пушем: убедиться что `node --check` прошёл без ошибок

## Экономия токенов
- Читай только нужные файлы, не весь проект сразу
- Для мелких правок — точечные изменения, не переписывать файл целиком
- Если задача непонятна — спроси одним коротким вопросом, не угадывай
- Подтверждай перед большими изменениями (>50 строк)
