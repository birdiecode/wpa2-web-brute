# wpa2 web brute

## Node.js-пакет и сборка

Node.js 20+. Сборка не требует сторонних npm-зависимостей:

```bash
npm run build
npm test
npm pack
```

Готовая страница: `dist/index.html`. Открывайте двойным щелчком или через
`file:///полный/путь/dist/index.html`. Сервер, CDN, fetch и загрузка ES-модулей
странице не нужны. Выбираются WebCrypto / WebGL2 / WebGPU, размер батча,
пароль, SSID, keyData, сообщение и ожидаемый MIC. Значения по умолчанию —
синтетический проверочный вектор. Батч повторяет введённый пароль;
проверяются все результаты. При изменении входов измените или очистите ожидаемый MIC.
Размер батча выбирается из выпадающего списка: 1, 2, 4, …, 32768.
Кнопка «Запустить тест» выполняет расчёт для выбранного размера.

В `dist/` создаются четыре независимые библиотеки:

| Имя | Содержимое |
| --- | --- |
| `wpa2-web-brute.webcrypto` | Только WebCrypto: PMK, PTK, MIC, полная цепочка |
| `wpa2-web-brute.webgl` | Только WebGL2: PMK, PTK, MIC, полная цепочка |
| `wpa2-web-brute.webgpu` | Только WebGPU: PMK, PTK, MIC, полная цепочка |
| `wpa2-web-brute.full` | Все три backend |

Для каждого варианта есть `.js` (обычный script, глобальный объект
`WPA2WebBrute`), `.mjs` (ESM) и `.cjs` (CommonJS). В браузере подключайте
один нужный вариант. GPU-контексты создаются только при явном вызове API.
Node.js используется для сборки и WebCrypto; GPU-реализациям нужна браузерная
среда. Поддержка WebGPU на file:// зависит от браузера, оборудования и его
настроек; страница показывает ошибку при недоступности выбранного API.

```html
<script src="./wpa2-web-brute.full.js"></script>
```

```js
import { WPA2WebCrypto, calc_pmk } from 'wpa2-web-brute/webcrypto';
const pmk = await calc_pmk('12345678', 'Test_WiFi');
const backend = await WPA2WebCrypto.create();
// keyData: Uint8Array(76), message: Uint8Array с обнулённым полем MIC.
const results = await backend.derive(['12345678'], 'Test_WiFi', keyData, message);
console.log(results[0].mic);
backend.dispose();
```

Экспорты: `calc_pmk(password, ssid)`, `calc_ptk(pmk, keyData)`,
`calc_mic(kck, message)`, `WPA2WebCrypto`; `WebGL2PMK`, `WebGL2PTK`,
`WebGL2MIC`, `WPA2WebGL`; `WebGPUPMK`, `WebGPUPTK`, `WebGPUMIC`, `WPA2WebGPU`.
WebGL создаётся через `new`, WebGPU — через `await Class.create()`.
Отдельные WebGL-этапы используют `derive()`, WebGPU-этапы — `calculate()`.
Полные цепочки используют `derive(passwords, ssid, keyData, message)`;
WebCrypto/WebGL возвращают `[{mic}]`, WebGPU — `{mics: Uint8Array[]}`.
После использования GPU вызывайте `dispose()` у экземпляра полной цепочки.

## Структура

- `src/` — исходники WebCrypto, WebGL2 и WebGPU.
- `demo/index.html` — шаблон тестовой страницы.
- `scripts/build.mjs` — сборка библиотек и страницы в `dist/`.
- `tests/` — проверки пакета и криптографических результатов.

`dist/` и npm-архивы генерируются командами сборки и не хранятся в Git.

## CLI через Puppeteer / Headless Chromium

```bash
npm install
npm run build
npm run cli -- --backend all
npm run cli -- --backend all --software
npm run cli -- --backend webgpu --input input.json --batch-size 256
npm run cli -- --help
```

После установки пакета доступна команда `wpa2-web-brute`. Все три бэкенда,
включая WebCrypto, выполняются внутри Headless Chromium. Puppeteer загружает
совместимый браузер при установке; собственный Chromium можно указать через
`--executable-path /path/to/chromium`. Используется современный
[headless-режим Puppeteer](https://pptr.dev/guides/headless-modes).

По умолчанию CLI запускает все бэкенды на синтетическом векторе из демо
и сверяет MIC. `--software` включает SwiftShader для WebGL2/WebGPU без
аппаратного GPU; этот режим медленнее. Доступность аппаратных бэкендов зависит
от драйверов и Chromium: ошибки каждого бэкенда попадают в отчёт, остальные
бэкенды продолжают выполняться. Дополнительные флаги браузера передаются
повторяемой опцией `--browser-arg=--имя-флага`.

`--input` принимает JSON следующего формата:

```js
{
  "passwords": ["12345678", "another-password"],
  "ssid": "Test_WiFi",
  "keyData": "…", // ровно 76 байт в hex, без пробелов и префикса 0x
  "message": "…"  // hex сообщения с уже обнулённым полем MIC
}
```

Замените многоточия реальными hex-данными и удалите комментарии для JSON.
`keyData` должен быть заранее упорядочен, как при вызове API библиотеки.
Необязательный `expectedMic` — 16 байт в hex для сравнения с каждым результатом.
Пароли: 8–63 байта UTF-8; SSID: 1–32 байта. `--batch-size` задаёт размер
частей входного массива (по умолчанию 1, максимум 32768); меньший лимит WebGPU
учитывается автоматически. Весь JSON загружается в память.

В stdout выводится JSON с `results`: имя бэкенда, `ok`, массив `mics`
в порядке входных паролей, время и, при наличии эталона, массив `matches`.
При ошибке бэкенда возвращается поле `error`. Пароли в отчёт не включаются.
Коды выхода: 0 — успех, 1 — ошибка бэкенда или несовпадение MIC,
2 — неверный ввод или ошибка запуска браузера. `--timeout` ограничивает
время одного бэкенда в миллисекундах (по умолчанию 120000).
Браузер и временный HTTP-сервер на `127.0.0.1` закрываются после работы.

`npm test` проверяет пакет и валидацию CLI. `npm run test:browser` дополнительно
запускает все три бэкенда через SwiftShader и сравнивает результат с Node crypto.
