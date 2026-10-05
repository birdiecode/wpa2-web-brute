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
