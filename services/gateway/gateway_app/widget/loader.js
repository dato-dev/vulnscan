/**
 * Загрузчик виджета. Это единственный наш код, который выполняется на странице
 * сайта, и он намеренно почти ничего не делает: создаёт iframe и слушает
 * сообщения от него.
 *
 * Так и задумано. Всё содержательное — выбор файла, чтение его байтов,
 * загрузка — происходит внутри фрейма, на нашем origin. Страница сайта к файлу
 * не прикасается, а мы не получаем доступ к её DOM. Обе стороны выигрывают:
 * сайт не рискует сломаться о вложение, а нам не приходится обосновывать право
 * выполнять код в чужой странице.
 *
 * Подключение:
 *
 *   <div data-vulnscan-key="acme-site-public"></div>
 *   <script src="https://scanner.example/widget/v1/loader.js" async></script>
 *
 * В форму добавляется скрытое поле `vulnscan_scan_id`. Бэкенд сайта ОБЯЗАН
 * запросить по нему вердикт своим секретным ключом: всё, что пришло со
 * страницы, написал браузер посетителя.
 */
(function () {
  "use strict";

  // Origin вычисляется из адреса самого скрипта, а не задаётся константой:
  // сервис разворачивают под своим доменом, и зашитый адрес означал бы правку
  // файла при каждой установке.
  var self = document.currentScript;
  var base = new URL(self.src, location.href);
  var WIDGET_ORIGIN = base.origin;

  function mount(host) {
    var key = host.getAttribute("data-vulnscan-key");
    if (!key) { return; }

    // Оформление: `data-vulnscan-accent="#123456"` уезжает параметром
    // `accent`. Список известных переменных — на сервере; неизвестное он
    // отбросит, поэтому проверять здесь нечего, а вот перечислять — вредно:
    // два списка разойдутся.
    var theme = "";
    for (var a = 0; a < host.attributes.length; a += 1) {
      var attribute = host.attributes[a];
      if (attribute.name.indexOf("data-vulnscan-") !== 0) { continue; }
      var name = attribute.name.slice("data-vulnscan-".length);
      if (name === "key" || name === "field") { continue; }
      theme += "&" + encodeURIComponent(name) + "=" + encodeURIComponent(attribute.value);
    }

    var frame = document.createElement("iframe");
    frame.src =
      WIDGET_ORIGIN +
      "/widget/v1/frame?key=" +
      encodeURIComponent(key) +
      "&origin=" +
      encodeURIComponent(location.origin) +
      theme;
    frame.title = "Проверка вложения";
    frame.style.border = "0";
    frame.style.width = "100%";
    frame.style.height = "72px";
    // Фрейму разрешено ровно необходимое. Без `allow-same-origin` он не
    // сможет обратиться к нашему API от своего имени, поэтому он здесь есть;
    // `allow-top-navigation` и `allow-popups` — нет, чтобы чужая страница не
    // могла быть уведена нашим фреймом.
    frame.setAttribute("sandbox", "allow-scripts allow-same-origin allow-forms");
    host.appendChild(frame);

    var field = document.createElement("input");
    field.type = "hidden";
    field.name = host.getAttribute("data-vulnscan-field") || "vulnscan_scan_id";
    host.appendChild(field);

    // Второе поле: почему `scan_id` пуст. Пустое значение означает «вложения
    // нет», но не объясняет причину — не приложили, заблокировано или не
    // проверилось. Бэкенду сайта разница важна.
    var stateField = document.createElement("input");
    stateField.type = "hidden";
    stateField.name = "vulnscan_state";
    host.appendChild(stateField);

    window.addEventListener("message", function (event) {
      // Две проверки, и обе обязательны.
      //
      // Origin — потому что сообщение может прислать любой фрейм на странице,
      // включая рекламный. Источник — потому что origin совпадёт и у второго
      // нашего фрейма, если сайт поставил на страницу две формы.
      if (event.origin !== WIDGET_ORIGIN) { return; }
      if (event.source !== frame.contentWindow) { return; }

      var data = event.data;
      if (!data || data.source !== "vulnscan") { return; }

      stateField.value = data.type || "";

      if (data.type === "checked" || data.type === "pending") {
        field.value = data.scan_id || "";
      } else {
        // Заблокировано, не проверено, идёт проверка — поля быть не должно.
        // Пустое значение на сервере сайта означает «вложения нет», и это
        // безопасное состояние.
        field.value = "";
      }

      host.dispatchEvent(
        new CustomEvent("vulnscan", { detail: data, bubbles: true }),
      );
    });
  }

  var hosts = document.querySelectorAll("[data-vulnscan-key]");
  for (var i = 0; i < hosts.length; i += 1) {
    mount(hosts[i]);
  }
})();
