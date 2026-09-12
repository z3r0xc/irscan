/* irscan desktop UI.
 *
 * The front end owns no detection logic. It does not decide severity, it does
 * not invent findings, it does not compute counts: the numbers on screen are the
 * backend's numbers, filtered and printed. Anything that looks like a rule about
 * what is suspicious belongs in the Rust core.
 *
 * Security: every string in the payload comes from a hostile host (service
 * paths, command lines, user names). Nothing here ever assigns markup. All
 * values go through textContent on nodes built with document.createElement.
 * innerHTML is never used, so a payload string containing a script end tag or
 * an attribute-shaped quote renders as literal text.
 */
(function () {
  "use strict";

  /* =========================================================== 0. strings ==
   * The UI language. Every visible string this file produces goes through
   * t(key, params): one lookup table, so a sentence can be found and changed
   * without hunting for it inside a renderer, and so the two languages cannot
   * drift apart one literal at a time.
   *
   * The backend's strings carry no keys and are NEVER translated: finding
   * titles, evidence lines, file paths, collector names, service names,
   * warnings, raw output and any Err(string) are data read off a hostile
   * machine, and they appear exactly as the core sent them. Translator-side
   * only: the report the shell writes is built by Rust and stays as it is.
   *
   * `{name}` in a value is replaced by params.name. Placeholders are positional
   * because a translator may need to move them: a language that puts the count
   * after the noun cannot be served by string concatenation.
   */

  var RU = {
    /* Header. */
    "host.none": "нет данных",
    "host.unknownName": "(имя узла недоступно)",
    "elev.unknown": "ПРАВА НЕИЗВЕСТНЫ",
    "elev.unknownTitle":
      "Сбор ещё не выполнялся, поэтому неизвестно, что именно удалось проверить.",
    "elev.yes": "ПРАВА АДМИНИСТРАТОРА",
    "elev.yesTitle":
      "Проверка выполнена с правами администратора: все коллекторы были доступны.",
    "elev.no": "БЕЗ ПРАВ - ЧАСТЬ ПРОВЕРОК ПРОПУЩЕНА",
    "elev.noTitle":
      "Проверка выполнена без прав администратора. Часть проверок не запустилась, " +
      "поэтому чистый результат здесь слабее, чем выглядит.",
    "save.report": "Сохранить отчёт",
    "save.json": "Сохранить JSON",
    "save.as": "сохранить как",
    "save.ok": "сохранено {path}",
    "save.fail": "не удалось сохранить: {message}",
    "cover.scanned": "проверка {at}",
    "cover.booted": "загрузка системы {at}",
    "cover.installed": "система установлена {at}",
    "cover.build": "сборка {build}",

    /* Scan button. */
    "scan.button": "Проверить",
    "scan.busy": "Идёт проверка",

    /* Verdict band. */
    "band.verdict": "ВЕРДИКТ",
    "sev.high": "ВЫСОКИЙ",
    "sev.med": "СРЕДНИЙ",
    "sev.info": "ИНФО",
    "rec.actions": "ЧТО ДЕЛАТЬ ДАЛЬШЕ",
    "band.notRun": "Проверка ещё не запускалась",

    /* Change strip. */
    "delta.heading": "ИЗМЕНЕНИЯ С ПРОШЛОЙ ПРОВЕРКИ",
    "delta.chip": "НОВОЕ",
    "delta.chipTitle": "появилось то, что переживёт перезагрузку",
    "delta.idle": "Сравнивать пока не с чем.",
    "delta.idleIncomplete": "Сравнивать не с чем: прошлая проверка не завершилась.",
    "delta.idleNone": "Ядро не прислало данные об изменениях для этой проверки.",
    "delta.first": "Первый запуск на этой машине. Следующая проверка покажет, что изменилось.",
    "delta.quiet": "С прошлой проверки ({since}) ничего не изменилось.",
    "delta.quietNoTime": "С прошлой проверки ничего не изменилось.",
    "delta.counts": "{n} новых, {m} пропало",
    "delta.since": "с {since}",
    "delta.more": "и ещё {n}",
    "delta.hint": "Нажмите на строку, чтобы скопировать название.",
    "delta.hintMiss": "Ничего не найдено по запросу «{label}».",
    "delta.copyTitle": "Скопировать «{subject}» в буфер обмена",
    "delta.copyTitleEmpty": "Скопировать пустое значение в буфер обмена",
    "delta.empty": "(пусто)",
    "delta.groupTitle": "Показать в списке находок только «{label}»",

    /* Delta groups. The lowercase words are also what a click types into the
       search box, and the findings it searches come from the core in English,
       so the query word stays English while the heading does not. */
    "kind.service": "службы",
    "kind.task": "задачи",
    "kind.autorun": "автозапуск",
    "kind.account": "учётные записи",
    "kind.process": "процессы",
    "kind.connection": "сетевые адреса",
    "kind.finding": "находки",
    "kind.other": "прочее",
    "query.services": "service",
    "query.tasks": "task",
    "query.autoruns": "run",
    "query.accounts": "account",
    "query.processes": "process",
    "query.connections": ":",
    "query.findings": "",

    /* Copy confirmation. */
    "copy.done": "скопировано",

    /* Collectors. The identifier stays Latin - it is the core's name for the
       collector and the only thing that can be searched for in the logs - and
       the human word is attached to it as a tooltip, not as a replacement. */
    "collector.accounts": "учётные записи",
    "collector.remote_access": "удалённый доступ",
    "collector.services": "службы",
    "collector.tasks": "задачи",
    "collector.autoruns": "автозапуск",
    "collector.wmi": "WMI-подписки",
    "collector.inputfilters": "драйверы ввода",
    "collector.defender": "Defender",
    "collector.processes": "процессы",
    "collector.network": "сеть",
    "collector.traces": "следы продуктов",
    "collector.filesystem": "файлы",
    "collector.events": "журнал событий",
    "collector.yara": "поиск по содержимому",

    /* Progress. */
    "progress.heading": "Проверка",
    "progress.reported": "отчитались {n} из них",
    "progress.finished": "завершено, отчитались коллекторов: {n}",
    "progress.unnamed": "(без имени)",

    /* Finding list. */
    "findings.label": "Находки",
    "findings.filterLabel": "Фильтр по уровню",
    "filter.all": "ВСЕ",
    "search.placeholder": "Поиск по находкам",
    "search.label": "Поиск находок по заголовку, категории или доказательству",
    "group.label": "Группы находок",
    "list.emptyTitle": "Проверка ещё не запускалась",
    "list.empty1": "Нажмите «Проверить», чтобы запустить все коллекторы: находки появятся здесь.",
    "list.empty2": " / - курсор в поиск, j и k - движение по списку, Esc - очистить.",
    "list.noMatchTitle": "Совпадений нет",
    "list.noMatch1":
      "Проверка сообщила о группах: {n}. Ни одна не подходит под этот уровень и текст поиска.",
    "list.noMatch2": "Нажмите Esc, чтобы очистить поиск, или верните фильтр на «ВСЕ».",
    "list.incompleteTitle": "Находок нет, но проверка выполнена не полностью",
    "list.incomplete1":
      "Предупреждений коллекторов: {n}. Часть проверок не запустилась, поэтому пустой список здесь значит очень мало.",
    "list.incomplete2":
      " Откройте «Сырые данные» внизу окна или запустите проверку с правами администратора, прежде чем считать машину чистой.",
    "list.cleanTitle": "Находок нет",
    "list.clean1":
      "Все коллекторы отработали и ничего не сообщили. Это не доказывает, что машина чиста: прочитайте примечание внизу окна.",
    "list.clean2": " Сырой вывод коллекторов доступен по кнопке «Сырые данные».",
    "row.untitled": "(находка без заголовка)",
    "row.instances": "экземпляров: {n}",

    /* Detail pane. */
    "detail.noScanTitle": "Проверка ещё не запускалась",
    "detail.noScan1":
      "Здесь показана одна находка целиком: её доказательства и что с ними делать.",
    "detail.noScan2": " Нажмите «Проверить» в заголовке, чтобы запустить коллекторы.",
    "detail.incompleteTitle": "Находок нет, но проверка выполнена не полностью",
    "detail.incomplete1":
      "Предупреждений коллекторов: {n}. Часть этой машины осталась необследованной.",
    "detail.incomplete2":
      " Пустой список находок после неполной проверки - не чистый результат. Запустите проверку с правами администратора и сравните.",
    "detail.cleanTitle": "Находок нет",
    "detail.clean1":
      "Проверка завершилась и ничего не обнаружила. Чистый результат не доказывает, что машина чиста.",
    "detail.clean2": " Сырой вывод коллекторов доступен по кнопке «Сырые данные» внизу.",
    "detail.hiddenTitle": "Выбранная находка скрыта фильтром",
    "detail.hidden1":
      "Выбранная находка не подходит под текущий уровень или текст поиска.",
    "detail.hidden2": " Нажмите Esc, чтобы очистить поиск, или верните фильтр на «ВСЕ».",
    "detail.instances": "экземпляров этой находки: {n}",
    "detail.evidence": "ДОКАЗАТЕЛЬСТВА",
    "detail.noEvidence": "У этой находки нет строк доказательств.",
    "detail.remediation": "ЧТО ДЕЛАТЬ",

    /* Containment. */
    "actions.title": "ДЕЙСТВИЯ",
    "actions.note":
      "Эти действия меняют машину. Каждое останавливает или убирает названный объект и " +
      "пишет запись отмены; больше ничего на диске не трогается. Введите идентификатор, " +
      "поставьте галочку, затем нажмите кнопку.",
    "actions.confirm": "Подтверждаю",
    "actions.confirmNote": "каждое действие вводится и подтверждается отдельно",
    "actions.service": "Отключить службу",
    "actions.serviceConsequence":
      "Служба будет остановлена и отключена. Файл и настройки остаются на диске - действие обратимо.",
    "actions.serviceField": "имя службы",
    "actions.servicePlaceholder": "например AcmeSupportSvc",
    "actions.serviceRequired": "Сначала введите имя службы.",
    "actions.autostart": "Удалить из автозапуска",
    "actions.autostartConsequence":
      "Запись будет удалена, её содержимое сохранится в записи отмены. Программа на диске не удаляется.",
    "actions.hiveField": "ветка реестра",
    "actions.keyField": "ключ",
    "actions.valueField": "значение",
    "actions.keyPlaceholder": "Software\...\Run",
    "actions.autostartRequired": "Нужны все три поля: ветка реестра, ключ и имя значения.",
    "actions.working": "Выполняется…",
    "actions.doneNoOutcome": "Готово.",
    "actions.doneLabel": "Готово: ",

    "actions.undo": "запись отмены: {path}",
    "actions.notDone": "Не выполнено: ",

    /* Warnings and raw data. */
    "warn.heading": "ПРЕДУПРЕЖДЕНИЯ",
    "warn.note": "Эти проверки не выполнились. Отчёт неполный.",
    "warn.none": "Проверка не запускалась, поэтому ничего не проверено.",
    "warn.clean": "Ни один коллектор не упал. Все проверки этой сборки отработали.",
    "raw.toggle": "Сырые данные",
    "raw.heading": "СЫРЫЕ ДАННЫЕ",
    "raw.noneTitle": "Сырых данных нет",
    "raw.none1":
      "Сырой вывод коллекторов появится здесь после проверки: списки процессов, определения служб и подобное - ровно в том виде, в каком они прочитаны с машины.",
    "raw.noSectionsTitle": "Сырых разделов нет",
    "raw.noSections1":
      "Эта проверка не дала сырого вывода. Обычно это значит, что она остановилась до того, как завершился хотя бы один коллектор - смотрите предупреждения.",
    "raw.unnamed": "(раздел без имени)",
    "raw.lines": "строк: {n}",
    "raw.empty": "(пусто)",
    "raw.count": "разделов: {n} · строк: {m}",

    /* Footer. */
    "foot.notProven":
      "Чистый результат не доказывает, что машина чиста: руткит уровня ядра или " +
      "переименованный агент без следов в реестре могут скрыться от всех проверок уровня " +
      "пользователя в этой проверке.",
    "foot.notRun":
      "Чистый результат не доказывает, что машина чиста. Проверка ещё не запускалась, " +
      "поэтому ничто на этом экране пока не проверено.",

    /* Errors raised by this file, not by the core. */
    "err.unknown": "неизвестная ошибка",
    "err.noCommand": "ядро не знает команду: {cmd}",
    "err.noServiceName": "Не указано имя службы.",
    "err.noAutostartValue": "Не указано имя значения автозапуска.",
    "err.noSuchService":
      "Службы с именем «{name}» на этой машине нет. Сверьте написание с разделом " +
      "SERVICES в сырых данных.",
    "err.noSuchAutostart":
      "Записи автозапуска с именем «{value}» нет в {hive}\{key}. Возможно, она уже удалена."
  };

  var EN = {
    "host.none": "no scan yet",
    "host.unknownName": "(host name unavailable)",
    "elev.unknown": "ELEVATION UNKNOWN",
    "elev.unknownTitle":
      "Nothing has been collected yet, so the coverage of the last run is unknown.",
    "elev.yes": "ELEVATED",
    "elev.yesTitle":
      "The scan ran with administrative rights; every collector was available.",
    "elev.no": "NOT ELEVATED - reduced coverage",
    "elev.noTitle":
      "The scan ran without administrative rights. Some checks did not run, so a clean " +
      "verdict here is weaker than it looks.",
    "save.report": "Save report",
    "save.json": "Save JSON",
    "save.as": "save as",
    "save.ok": "saved {path}",
    "save.fail": "could not save: {message}",
    "cover.scanned": "scanned {at}",
    "cover.booted": "booted {at}",
    "cover.installed": "installed {at}",
    "cover.build": "build {build}",

    "scan.button": "Scan",
    "scan.busy": "Scanning",

    "band.verdict": "Verdict",
    "sev.high": "HIGH",
    "sev.med": "MED",
    "sev.info": "INFO",
    "rec.actions": "Recommended actions",
    "band.notRun": "No scan has been run yet.",

    "delta.heading": "Changes since the last scan",
    "delta.chip": "NEW PRESENCE",
    "delta.chipTitle": "there is something here that survives a reboot",
    "delta.idle": "Nothing to compare yet.",
    "delta.idleIncomplete": "Nothing to compare: the last run did not complete.",
    "delta.idleNone": "The backend sent no change data for this run.",
    "delta.first": "First run on this machine. The next scan will show what changed.",
    "delta.quiet": "Nothing changed since {since}.",
    "delta.quietNoTime": "Nothing changed.",
    "delta.counts": "{n} new, {m} gone",
    "delta.since": "since {since}",
    "delta.more": "and {n} more",
    "delta.hint": "Click an entry to copy its name.",
    "delta.hintMiss": "No finding matches \"{label}\".",
    "delta.copyTitle": "Copy \"{subject}\" to the clipboard",
    "delta.copyTitleEmpty": "Copy an empty value to the clipboard",
    "delta.empty": "(empty)",
    "delta.groupTitle": "Filter the finding list to {label}",

    "kind.service": "services",
    "kind.task": "scheduled tasks",
    "kind.autorun": "autostart entries",
    "kind.account": "accounts",
    "kind.process": "processes",
    "kind.connection": "remote endpoints",
    "kind.finding": "findings",
    "kind.other": "other",
    "query.services": "service",
    "query.tasks": "task",
    "query.autoruns": "run",
    "query.accounts": "account",
    "query.processes": "process",
    "query.connections": ":",
    "query.findings": "",

    "copy.done": "copied",

    "collector.accounts": "accounts",
    "collector.remote_access": "remote access",
    "collector.services": "services",
    "collector.tasks": "tasks",
    "collector.autoruns": "autoruns",
    "collector.wmi": "WMI subscriptions",
    "collector.inputfilters": "input filters",
    "collector.defender": "Defender",
    "collector.processes": "processes",
    "collector.network": "network",
    "collector.traces": "product traces",
    "collector.filesystem": "filesystem",
    "collector.events": "event log",
    "collector.yara": "content search",

    "progress.heading": "Scanning",
    "progress.reported": "{n} of them reported",
    "progress.finished": "finished · {n} collector(s) reported",
    "progress.unnamed": "(unnamed)",

    "findings.label": "Findings",
    "findings.filterLabel": "Filter by severity",
    "filter.all": "All",
    "search.placeholder": "Search titles and evidence",
    "search.label": "Search findings by title, category or evidence",
    "group.label": "Finding groups",
    "list.emptyTitle": "Nothing scanned yet",
    "list.empty1": "Press Scan to run every collector and list the findings here.",
    "list.empty2": " / focuses the search box, j and k move the selection, Esc clears.",
    "list.noMatchTitle": "No findings match",
    "list.noMatch1":
      "The scan reported {n} group(s); none of them match this severity filter and search text.",
    "list.noMatch2": " Press Esc to clear the search, or set the filter back to All.",
    "list.incompleteTitle": "No findings, but the scan was incomplete",
    "list.incomplete1":
      "{n} collector warning(s): some checks did not run, so an empty list here means very little.",
    "list.incomplete2":
      " Open Raw data at the bottom of the window, or re-run elevated, before treating this machine as clean.",
    "list.cleanTitle": "No findings",
    "list.clean1":
      "Every collector ran and reported nothing. That is not proof of a clean machine - read the note along the bottom of the window.",
    "list.clean2": " Raw collector output is still available from the Raw data button.",
    "row.untitled": "(untitled finding)",
    "row.instances": "{n} instances",

    "detail.noScanTitle": "No scan has been run",
    "detail.noScan1":
      "This pane shows one finding in full: its evidence lines and what to do about them.",
    "detail.noScan2": " Press Scan in the header to run the collectors.",
    "detail.incompleteTitle": "No findings, but the scan was incomplete",
    "detail.incomplete1":
      "{n} collector warning(s) mean part of this machine was never examined.",
    "detail.incomplete2":
      " An empty finding list from an incomplete scan is not a clean result. Re-run elevated and compare.",
    "detail.cleanTitle": "No findings to show",
    "detail.clean1":
      "The scan completed and reported no indicators. A clean result is not proof of a clean machine.",
    "detail.clean2":
      " Raw collector output is available from the Raw data button at the bottom.",
    "detail.hiddenTitle": "Selection hidden by the filter",
    "detail.hidden1":
      "The selected finding does not match the current severity filter or search text.",
    "detail.hidden2": " Press Esc to clear the search, or set the filter back to All.",
    "detail.instances": "{n} instances of this finding",
    "detail.evidence": "Evidence",
    "detail.noEvidence": "This finding carried no evidence lines.",
    "detail.remediation": "Remediation",

    "actions.title": "Actions",
    "actions.note":
      "These change this machine. Each one stops or removes the named thing and " +
      "writes an undo record; nothing else on disk is touched. Type the identifier, " +
      "tick Confirm, then press the button.",
    "actions.confirm": "Confirm",
    "actions.confirmNote": "typed, confirm each one",
    "actions.service": "Disable service",
    "actions.serviceConsequence":
      "Stops the service and sets its startup to disabled. The service is NOT " +
      "deleted, and its image on disk is NOT touched.",
    "actions.serviceField": "service name",
    "actions.servicePlaceholder": "e.g. AcmeSupportSvc",
    "actions.serviceRequired": "Enter the service name first.",
    "actions.autostart": "Remove autostart",
    "actions.autostartConsequence":
      "Deletes one value under a Run or RunOnce key. The program it pointed at is " +
      "NOT deleted, and ROT13-protected entries are NOT followed.",
    "actions.hiveField": "hive",
    "actions.keyField": "key",
    "actions.valueField": "value",
    "actions.keyPlaceholder": "Software\\...\\Run",
    "actions.autostartRequired": "All three fields are needed: hive, key and value name.",
    "actions.working": "Working\u2026",
    "actions.doneNoOutcome": "Done.",
    "actions.doneLabel": "Done: ",
    "actions.undo": "undo record: {path}",
    "actions.notDone": "Not done: ",

    "warn.heading": "Warnings",
    "warn.note": "A warning means a check did not run. The report is incomplete.",
    "warn.none": "No scan has been run, so nothing has been checked.",
    "warn.clean": "No collector failed. Every check in this build ran.",
    "raw.toggle": "Raw data",
    "raw.heading": "Raw data",
    "raw.noneTitle": "No raw data",
    "raw.none1":
      "Raw collector output appears here after a scan: process lists, service definitions and the like, exactly as they were read from the machine.",
    "raw.noSectionsTitle": "No raw sections",
    "raw.noSections1":
      "This scan produced no raw output. That usually means it stopped before any collector finished - check the warnings.",
    "raw.unnamed": "(unnamed section)",
    "raw.lines": "{n} line(s)",
    "raw.empty": "(empty)",
    "raw.count": "{n} section(s) \u00B7 {m} line(s)",

    "foot.notProven":
      "A clean result is not proof that the machine is clean: a kernel-mode rootkit or a " +
      "renamed agent with no registry trace can hide from every user-mode check in this scan.",
    "foot.notRun":
      "A clean result is not proof of a clean machine. No scan has been run yet, so nothing " +
      "on this screen has been checked.",

    "err.unknown": "unknown error",
    "err.noCommand": "no such command: {cmd}",
    "err.noServiceName": "No service name was given.",
    "err.noAutostartValue": "No autostart value name was given.",
    "err.noSuchService":
      "No service named \"{name}\" exists on this machine. Check the spelling against the " +
      "SERVICES section of the raw data.",
    "err.noSuchAutostart":
      "No autostart entry named \"{value}\" under {hive}\\{key}. It may already have been removed."
  };

  /* Which language to speak. There is no switch in the UI: the machine already
     answers this question, and a second source of truth for it could only
     disagree with the shell's own locale. Anything that does not start with
     "ru" is English, including an empty or unreadable navigator. */
  var LANG = (function () {
    var n = null;
    try { n = typeof navigator !== "undefined" ? navigator : null; } catch (e) { n = null; }
    var tag = n ? (n.languages && n.languages.length ? n.languages[0] : n.language) : "";
    return /^ru\b/i.test(String(tag || "")) ? "ru" : "en";
  }());

  var DICT = LANG === "ru" ? RU : EN;
  var FALLBACK = LANG === "ru" ? EN : RU;

  /**
   * The one way a visible string is produced.
   * @param {string} key    dictionary key, e.g. "scan.button"
   * @param {object} params values for the {name} placeholders in the value
   * @returns {string} the sentence, with placeholders substituted
   */
  function t(key, params) {
    var s = Object.prototype.hasOwnProperty.call(DICT, key) ? DICT[key]
      : (FALLBACK[key] === undefined ? String(key) : FALLBACK[key]);
    if (!params) return s;
    return s.replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, function (whole, name) {
      var v = params[name];
      return v === undefined || v === null ? whole : String(v);
    });
  }

  /**
   * Fill the static text in index.html from the dictionary. Everything a reader
   * sees has to come from one place, or the file becomes untranslatable one
   * literal at a time: the markup carries a key, this writes the value. Runs
   * once, before the first render. The English text in the markup is the
   * fallback for a browser that never runs this, not a second translation.
   */
  function applyI18n(root) {
    var doc = root || document;
    var nodes = doc.querySelectorAll("[data-i18n]");
    var i;
    for (i = 0; i < nodes.length; i++) {
      nodes[i].textContent = t(nodes[i].getAttribute("data-i18n"));
    }
    nodes = doc.querySelectorAll("[data-i18n-aria]");
    for (i = 0; i < nodes.length; i++) {
      nodes[i].setAttribute("aria-label", t(nodes[i].getAttribute("data-i18n-aria")));
    }
    nodes = doc.querySelectorAll("[data-i18n-placeholder]");
    for (i = 0; i < nodes.length; i++) {
      nodes[i].setAttribute("placeholder", t(nodes[i].getAttribute("data-i18n-placeholder")));
    }
    try { doc.documentElement.setAttribute("lang", LANG); } catch (e) { /* no documentElement */ }
  }

  /* ============================================================ 1. adapter ==
   * The only place in this file that knows Tauri exists. Everything below the
   * adapter works on plain data, which is what keeps the browser fallback from
   * rotting and keeps the rest testable without a shell.
   */
  var Backend = (function () {
    function api() {
      var t = typeof window !== "undefined" ? window.__TAURI__ : null;
      return t && t.core && t.event ? t : null;
    }

    return {
      /** True when a real shell answered. */
      isLive: function () { return api() !== null; },

      /**
       * Call a backend command.
       * @param {string} cmd  command name, e.g. "scan"
       * @param {object} args command arguments
       * @returns {Promise<object>} the payload. Outside a shell this resolves
       *   with the demo payload. A rejection means the command failed and is
       *   surfaced as an error state.
       */
      invoke: function (cmd, args) {
        var t = api();
        if (t) return t.core.invoke(cmd, args || {});
        return demoCall(cmd, args);
      },

      /**
       * Subscribe to a backend event.
       * @param {string} name      e.g. "scan://progress"
       * @param {function} handler receives the event payload
       * @returns {Promise<function>} resolves to an unsubscribe function
       */
      listen: function (name, handler) {
        var t = api();
        if (t) {
          return t.event.listen(name, function (e) { handler(e.payload); })
            .then(function (un) { return function () { un(); }; });
        }
        return demoListen(name, handler);
      },

      /**
       * Ask the shell where a file should be written.
       * @param {object} opts { defaultPath, filters }
       * @returns {Promise<string|null>} the chosen path, or null if the user
       *   cancelled. Without the dialog plugin (browser, demo) this resolves to
       *   null and the caller falls back to its own path input.
       */
      save: function (opts) {
        var t = typeof window !== "undefined" ? window.__TAURI__ : null;
        var d = t && t.dialog;
        if (!d || typeof d.save !== "function") return Promise.resolve(null);
        try {
          return Promise.resolve(d.save(opts || {})).then(function (path) {
            return path == null ? null : String(path);
          });
        } catch (e) {
          return Promise.resolve(null);
        }
      },

      /** True when a real path picker exists, so the UI knows to skip its
       *  fallback text input. */
      hasDialog: function () {
        var t = typeof window !== "undefined" ? window.__TAURI__ : null;
        return !!(t && t.dialog && typeof t.dialog.save === "function");
      }
    };
  }());

  /* ======================================================= 2. demo payload ==
   * The fallback payload. It exists so the page renders in a plain browser for
   * design review, and so a missing shell degrades to something readable rather
   * than a blank screen. It deliberately exercises every part of the UI - three
   * severities, six groups, multi-line evidence, a group with instances > 1,
   * warnings, raw sections - and it carries one hostile string: the fourth
   * service evidence line below contains a `<` , a `>` and embedded quotes, and
   * it must appear on screen as literal characters.
   *
   * Its prose is translated, and not for consistency: this payload is the whole
   * product for the only reader who ever sees it - a person opening a browser to
   * find out what this tool says. An example that answers in a language the tool
   * no longer speaks reviews nothing. Host names, user names, paths, service
   * names and collector identifiers inside it are data and stay as they are. A
   * real run never reads any of this.
   */
  /* The three delta states, so every branch of the strip is reachable in a
  browser. `?delta=first|quiet|changed` picks one; see demoCall("scan").
  All three are the same shape the backend sends, null `since` included. */
  var DEMO_DELTA_FIRST = {
  "since": null,
  "added": [],
  "removed": [],
  "summary": "",
  "newPresence": false,
  "firstRun": true
  };

  var DEMO_DELTA_QUIET = {
  "since": "2026-09-11 21:04:15",
  "added": [],
  "removed": [],
  "summary": "",
  "newPresence": false,
  "firstRun": false
  };

  /* Twelve added and three removed across six kinds, so the per-group cap of 8
  and the "and N more" line are both visible on screen. */
  var DEMO_DELTA_CHANGED = {
  "since": "2026-09-11 22:10:04",
  "added": [
  { "kind": "service", "subject": "AcmeSupportSvc" },
  { "kind": "service", "subject": "AcmeHealthSvc" },
  { "kind": "service-image", "subject": "C:\\ProgramData\\~tmp\\svc2.exe" },
  { "kind": "service", "subject": "AcmeTelemetrySvc" },
  { "kind": "service", "subject": "AcmeWatchdogSvc" },
  { "kind": "service", "subject": "AcmeUpdater" },
  { "kind": "service", "subject": "AcmeRemoteCtl" },
  { "kind": "service", "subject": "AcmeLogShip" },
  { "kind": "service", "subject": "AcmeProbeSvc" },
  { "kind": "task", "subject": "\\AcmeHealthCheck" },
  { "kind": "task", "subject": "\\AcmeUpdate" },
  { "kind": "autorun", "subject": "HKCU\\...\\Run\\AcmeAgent" },
  { "kind": "account", "subject": "rinat" },
  { "kind": "process", "subject": "acsupport.exe" },
  { "kind": "process", "subject": "health.exe" },
  { "kind": "connection", "subject": "203.0.113.42:443" },
  { "kind": "connection", "subject": "198.51.100.7:8443" },
  { "kind": "finding", "subject": "Неподписанный файл в доступном для записи каталоге" }
  ],
  "removed": [
  { "kind": "process", "subject": "old.exe" },
  { "kind": "connection", "subject": "10.0.0.14:3389" },
  { "kind": "service", "subject": "LegacyAgentSvc" }
  ],
  "summary": "",
  "newPresence": true,
  "firstRun": false
  };

  var DEMO_PAYLOAD = {
    "host": {
      "name": "LUXTVTZ",
      "user": "rinat",
      "os": "Windows 10 Pro",
      "build": "28000.2704",
      "installDate": "2026-08-05 21:48:27",
      "bootTime": "2026-09-04 13:58:39",
      "elevated": false,
      "collectedAt": "2026-09-11 21:04:15",
      "scannedInMs": 9240
    },
    "verdict": {
      "high": 1,
      "med": 4,
      "info": 83,
      "headline": "Находок уровня ВЫСОКИЙ: 1 — есть конкретные признаки скрытого наблюдения или удалённого управления. Предупреждений коллекторов: 2, часть проверок не запустилась; смотрите отчёт.",
      "recommendation": [
        "Сначала отключите машину от сети: это немедленно прекращает выгрузку экрана и удалённое управление и не уничтожает местные доказательства.",
        "Не удаляйте неподписанный файл в %TEMP%: сначала скопируйте его и отчёт на внешний носитель.",
        "Пока ничего не удаляйте. Скопируйте отчёт и строки доказательств на внешний носитель.",
        "Если найден неизвестный агент — прежде всего неподписанный файл в доступном для записи каталоге с активным исходящим соединением — считайте машину полностью скомпрометированной. Современный RAT надёжно убирает только чистая переустановка системы с внешнего носителя.",
        "Смените все пароли с ДРУГОГО, заведомо чистого устройства, начиная с почты: почта — это канал сброса для всего остального. Включите двухфакторную аутентификацию и отзовите активные сеансы и токены.",
        "После устранения запустите эту проверку снова и сравните: если те же находки вернулись, значит механизм закрепления сохранился."
      ]
    },
    "groups": [
      {
        "severity": "high",
        "category": "process",
        "title": "Неподписанный файл в доступном для записи каталоге с активным исходящим соединением",
        "instances": 1,
        "evidence": [
          "pid=4218 image=C:\\Users\\rinat\\AppData\\Local\\Temp\\AkB7x9\\host.exe unsigned=true",
          "remote=203.0.113.42:443 ESTABLISHED age=00:14:22, 198.51.100.7:8443 ESTABLISHED age=00:02:03",
          "parent=explorer.exe session=1 user=rinat",
          "файл лежит в %TEMP% и не упомянут ни в одной службе, задаче или записи автозапуска"
        ],
        "remediation": [
          "Считайте эту машину скомпрометированной. Неподписанный исполняемый файл во временном каталоге, доступном пользователю для записи, с исходящим сеансом к хостинг-провайдеру — это стандартный облик агента удалённого управления.",
          "Отключите её от сети прежде всего остального и не удаляйте файл: он и есть доказательство."
        ]
      },
      {
        "severity": "med",
        "category": "accounts",
        "title": "Локальная учётная запись: rinat",
        "instances": 1,
        "evidence": [
          "enabled=true admin=true guest=false last logon=never password required=false",
          "sid=S-1-5-21-3091726520-2945084116-2158671362-1001",
          "profile=C:\\Users\\rinat\\"
        ],
        "remediation": [
          "Уточните у владельца машины, что это за учётная запись. Учётная запись администратора, которой ни разу не пользовались, — это либо остаток от развёртывания образа, либо запись, созданная для кого-то ещё.",
          "Если владелец её не узнаёт, отключите её прежде всего остального."
        ]
      },
      {
        "severity": "med",
        "category": "service",
        "title": "Служба запускается из доступного для записи каталога",
        "instances": 4,
        "evidence": [
          "name=AcmeSupportSvc display=\"Acme Support Service\" start=auto state=running",
          "image=C:\\Users\\rinat\\AppData\\Local\\Acme\\bin\\acsupport.exe --service --no-window",
          "image=C:\\ProgramData\\~tmp\\svc2.exe -k netsvcs",
          "image=C:\\Windows\\Temp\\<cfg name=\"update\">\\runner.exe --silent",
          "image=C:\\Users\\Public\\Documents\\agent.exe"
        ],
        "remediation": [
          "Файл службы в %LOCALAPPDATA%, %TEMP% или C:\\Users\\Public может подменить любой пользователь машины. Прежде чем что-то удалять, уточните поставщика.",
          "Сверьте имя файла с базой подписей и с тем, какое ПО владелец ожидает увидеть установленным."
        ]
      },
      {
        "severity": "med",
        "category": "remote-access",
        "title": "Включён удалённый рабочий стол",
        "instances": 1,
        "evidence": [
          "fDenyTSConnections=0",
          "TermService=auto/running, port 3389 listening on 0.0.0.0",
          "last successful RDP logon=2026-08-30 02:14:11 from 10.0.0.14"
        ],
        "remediation": [
          "Если удалённым рабочим столом здесь никто не пользуется, отключите его и проверьте на роутере проброс порта 3389.",
          "Источник 10.0.0.14 находится внутри локальной сети: значит, сеанс начался с другой машины в этой же сети."
        ]
      },
      {
        "severity": "info",
        "category": "scheduled-task",
        "title": "Задача в планировщике с необычным триггером",
        "instances": 7,
        "evidence": [
          "name=\\MicrosoftEdgeUpdateTaskMachineUA trigger=logon action=C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /ua",
          "name=\\AcmeHealthCheck trigger=every 5 minutes, repeat forever action=C:\\Users\\rinat\\AppData\\Roaming\\Acme\\health.exe",
          "name=\\OneDriveStandaloneUpdater author=\\rinat"
        ],
        "remediation": [
          "Большинство из них — обновлятели от известных поставщиков. Те, что созданы незнакомым поставщиком, стоит опознать, прежде чем машина снова пойдёт в работу."
        ]
      },
      {
        "severity": "med",
        "category": "autoruns",
        "title": "Запись автозапуска в пользовательском ключе Run",
        "instances": 1,
        "evidence": [
          "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run: AcmeAgent = C:\\Users\\rinat\\AppData\\Roaming\\Acme\\agent.exe --silent",
          "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce: AcmeSetup = C:\\Users\\Public\\setup.exe",
          "значение добавлено 2026-09-11 22:04, уже после прошлой проверки"
        ],
        "remediation": [
          "Запись в ключе Run, указывающая в доступный для записи каталог, переживает перезагрузку и запускается раньше, чем кто-либо успеет войти и её остановить.",
          "Экспортируйте ключ до удаления значения, чтобы точный путь остался в документах."
        ]
      },
      {
        "severity": "info",
        "category": "network",
        "title": "Установленное исходящее соединение с хостинг-провайдером",
        "instances": 12,
        "evidence": [
          "pid=4218 acsupport.exe -> 203.0.113.42:443 ESTABLISHED age=00:14:22",
          "pid=4218 acsupport.exe -> 198.51.100.7:8443 ESTABLISHED age=00:02:03",
          "pid=1104 svchost.exe -> 52.113.194.132:443 ESTABLISHED"
        ],
        "remediation": [
          "Долго живущий сеанс с одним и тем же адресом похож на канал удалённого управления, но браузеры и обновлятели выглядят точно так же.",
          "Прежде чем делать вывод, сверьте идентификатор процесса со списком процессов."
        ]
      },
      {
        "severity": "info",
        "category": "input",
        "title": "Присутствует Scancode Map клавиатуры",
        "instances": 1,
        "evidence": [
          "hklm\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\Scancode Map: 00000000 00000000 03000000 5BE00000 00003A00 00000000",
          "расшифровка: Left-Ctrl переназначен на Left-Win, а Win — ни на что"
        ],
        "remediation": [
          "Переназначение скан-кодов используют и некоторые программы для клавиатуры, и кейлоггеры, которым нужно пережить экран Ctrl-Alt-Del.",
          "Если владелец не устанавливал ПО для переназначения клавиш, экспортируйте значение до удаления ключа."
        ]
      }
    ],
    "warnings": [
      "events: журнал безопасности недоступен: EvtQuery завершился с ошибкой Win32 5 (отказано в доступе) — запустите с правами администратора, чтобы получить историю входов и установки служб",
      "traces: не удалось прочитать C:\\Windows\\Prefetch\\ACSUPPORT.EXE-1A2B3C4D.pf (ошибка Win32 5)"
    ],
    "raw": [
      {
        "section": "PROCESSES",
        "lines": [
          "pid 1  System",
          "pid 1104 svchost.exe \"C:\\Windows\\system32\\svchost.exe\" -k netsvcs",
          "pid 4218 acsupport.exe \"C:\\Users\\rinat\\AppData\\Local\\Acme\\bin\\acsupport.exe\" --service --no-window",
          "pid 6692 explorer.exe \"C:\\Windows\\explorer.exe\""
        ]
      },
      {
        "section": "SERVICES",
        "lines": [
          "AcmeSupportSvc auto running \"C:\\Users\\rinat\\AppData\\Local\\Acme\\bin\\acsupport.exe\" --service",
          "TermService auto running C:\\Windows\\System32\\svchost.exe -k NetworkService",
          "WinDefend auto running \"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe\""
        ]
      },
      {
        "section": "PREFETCH",
        "lines": [
          "(записей нет: коллектор не запускался)"
        ]
      }
    ],
    "notProven": "Чистый результат не доказывает, что машина чиста: руткит уровня ядра или переименованный агент без следов в реестре могут скрыться от всех проверок уровня пользователя в этой проверке.",
    "cursor": 1,
    "delta": DEMO_DELTA_CHANGED
  };

  /** Collector order and names, mirrored from the Rust core for demo pacing only. */
  var DEMO_COLLECTORS = [
    "accounts", "remote_access", "services", "tasks", "autoruns", "wmi",
    "inputfilters", "defender", "processes", "network", "traces",
    "filesystem", "events", "yara"
  ];

  var DEMO_APP_INFO = { version: "0.1.0", needles: 1911, yaraRules: 6, collectors: 14 };

  /**
   * Which delta state the demo run reports. Read once from the URL so a
   * reviewer can put the strip in each of its three states without a backend:
   *   index.html?delta=first    a first run on this machine (the default)
   *   index.html?delta=quiet    a later run, nothing changed
   *   index.html?delta=changed  a later run, 12 new and 3 gone
   * The parameter is not read anywhere else, and a shell ignores it entirely.
   */
  function demoDeltaState() {
    var q = "";
    try { q = String(window.location.search || ""); } catch (e) { q = ""; }
    var m = /[?&]delta=([a-z]+)/.exec(q);
    var v = m ? m[1] : "changed";
    if (v === "first") return DEMO_DELTA_FIRST;
    if (v === "quiet") return DEMO_DELTA_QUIET;
    return DEMO_DELTA_CHANGED;
  }

  /**
   * Stand-in for the containment commands. The identifier that is not on the
   * machine rejects with a plain string, exactly the shape the shell returns
   * through Err(string), so the UI's error path is reachable in a browser.
   */
  var DEMO_KNOWN_SERVICES = ["AcmeSupportSvc", "AcmeHealthSvc", "TermService", "WinDefend"];
  var DEMO_KNOWN_AUTORUNS = ["AcmeAgent", "OneDriveSetup", "SecurityHealth"];

  function demoRemediate(cmd, args) {
    var a = args || {};
    if (cmd === "disable_service") {
      var name = String(a.name == null ? "" : a.name).trim();
      if (!name) return Promise.reject(t("err.noServiceName"));
      if (DEMO_KNOWN_SERVICES.indexOf(name) === -1) {
        return Promise.reject(t("err.noSuchService", { name: name }));
      }
      return Promise.resolve({
        description: "Stop and disable the service \"" + name + "\".",
        outcome: LANG === "ru"
          ? "Служба остановлена и переведена в отключённые. Сама служба НЕ удалена, её файл на диске не тронут."
          : "Stopped and set to disabled. The service is NOT deleted, and its image on disk is untouched.",
        undoPath: "C:\\Users\\rinat\\AppData\\Local\\irscan\\undo\\disable-" + name + ".json"
      });
    }
    if (cmd === "remove_autostart") {
      var value = String(a.value == null ? "" : a.value).trim();
      if (!value) return Promise.reject(t("err.noAutostartValue"));
      if (DEMO_KNOWN_AUTORUNS.indexOf(value) === -1) {
        return Promise.reject(t("err.noSuchAutostart",
          { value: value, hive: a.hive || "HKCU", key: a.key || "" }));
      }
      return Promise.resolve({
        description: "Delete the autostart value \"" + value + "\".",
        outcome: LANG === "ru"
          ? "Значение удалено из реестра. Программа на диске НЕ удалена."
          : "Value deleted from the registry. The program on disk is NOT deleted.",
        undoPath: "C:\\Users\\rinat\\AppData\\Local\\irscan\\undo\\autorun-" + value + ".json"
      });
    }
    return Promise.reject(t("err.noCommand", { cmd: cmd }));
  }

  function demoCall(cmd, args) {
    if (cmd === "app_info") return Promise.resolve(DEMO_APP_INFO);
    if (cmd === "export_report") {
      return Promise.resolve((args && args.path) || "C:\\Users\\x\\report.txt");
    }
    if (cmd === "disable_service" || cmd === "remove_autostart") {
      return demoRemediate(cmd, args);
    }
    if (cmd === "scan") {
      demoRunProgress();
      var payload = {};
      var k;
      for (k in DEMO_PAYLOAD) {
        if (Object.prototype.hasOwnProperty.call(DEMO_PAYLOAD, k)) payload[k] = DEMO_PAYLOAD[k];
      }
      payload.delta = demoDeltaState();
      return Promise.resolve(payload);
    }
    return Promise.reject(new Error(t("err.noCommand", { cmd: cmd })));
  }

  var progressHandler = null;

  /**
   * Stand-in for event.listen. Only scan://progress is emulated, replaying one
   * collector at a time so the progress list can be looked at without a shell.
   * One collector fails, because that is the normal case the UI must survive.
   */
  function demoListen(name, handler) {
    if (name !== "scan://progress") return Promise.resolve(function () {});
    progressHandler = handler;
    return Promise.resolve(function () { progressHandler = null; });
  }

  function demoRunProgress() {
    var handler = progressHandler;
    if (!handler) return;
    var added = [0, 1, 4, 3, 6, 0, 2, 1, 5, 12, 1, 9, 205, 0];
    DEMO_COLLECTORS.forEach(function (c, i) {
      window.setTimeout(function () {
        handler({
          collector: c,
          elapsedMs: 120 + i * 730,
          findingsAdded: added[i],
          error: c === "events"
            ? "журнал безопасности недоступен: EvtQuery завершился с ошибкой Win32 5 (отказано в доступе)"
            : null
        });
      }, 90 + i * 90);
    });
  }

  /* ============================================================ 3. helpers ==
   * Plain data help. None of these decide anything about the host.
   */

  var SEVERITY_ORDER = { high: 0, med: 1, info: 2 };
  /* The severity keys are the backend's, and the letters on screen are this
     file's: a tag is a key too, and it has to be translated like one. */
  var SEVERITY_KEY = { high: "sev.high", med: "sev.med", info: "sev.info" };
  var SEVERITY_GLYPH = { high: "\u25CF", med: "\u25D0", info: "\u25CB" };

  function sevKey(sev) {
    return SEVERITY_KEY[sev] || "sev.info";
  }
  function label(sev) { return t(sevKey(sev)); }
  function glyph(sev) { return SEVERITY_GLYPH[sev] || "\u25CB"; }

  /* Every node below is built with these two helpers. Both use textContent, so
     a payload string is never parsed as markup. */
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function asArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]" ? v : [];
  }

  /** Sum findings per severity from the payload's groups. No rules, just sums. */
  function tally(groups) {
    var t = { all: 0, high: 0, med: 0, info: 0 };
    asArray(groups).forEach(function (g) {
      var s = g && g.severity;
      if (t[s] === undefined) return;
      var n = typeof g.instances === "number" && g.instances > 0 ? g.instances : 1;
      t[s] += n;
    });
    t.all = t.high + t.med + t.info;
    return t;
  }

  /** One lowercased haystack per group, so typing does not rebuild it per keystroke. */
  function searchText(g) {
    var parts = [g.title, g.category];
    asArray(g.evidence).forEach(function (e) { parts.push(e); });
    asArray(g.remediation).forEach(function (e) { parts.push(e); });
    return parts.join("\n").toLowerCase();
  }

  /* Human words for the delta's `kind`. The strip is read by a person, not by
     this file, so "service-image" must not reach the screen. Two kinds share a
     column by sharing a key, which is what merges `service` and `service-image`
     into the one "services" column a reader expects. The keys index KIND_LABEL
     and, through the same word, KIND_QUERY below. */
  var KIND_LABEL = {
    "service": "kind.service",
    "service-image": "kind.service",
    "task": "kind.task",
    "autorun": "kind.autorun",
    "account": "kind.account",
    "process": "kind.process",
    "process-path": "kind.process",
    "connection": "kind.connection",
    "finding": "kind.finding"
  };
  var KIND_OTHER = "kind.other";

  /* Order the groups are laid out in: the things that persist across a reboot
     first, the noisy per-boot facts last. Kinds sharing a `group` line up. */
  var KIND_ORDER = [
    "service", "service-image", "task", "autorun", "account",
    "process", "process-path", "connection", "finding"
  ];

  /* The word a click on a group applies to the finding search box. It is the
     word that actually appears in titles and evidence for that kind, which is
     why it is not simply the plural shown in the heading ("services" matches no
     finding; "service" matches the service ones).
     Keyed by label KEY, not by the word on screen: a translated heading would
     otherwise silently stop matching, and the click would type a Russian word
     into a list of English findings and return nothing. It is an English word
     because the thing it searches is the backend's English. */
  var KIND_QUERY = {
    "kind.service": "query.services",
    "kind.task": "query.tasks",
    "kind.autorun": "query.autoruns",
    "kind.account": "query.accounts",
    "kind.process": "query.processes",
    "kind.connection": "query.connections",
    "kind.finding": "query.findings"
  };

  var MAX_PER_GROUP = 8;

  /** The dictionary key of a delta kind's human name. */
  function kindKey(kind) {
    return Object.prototype.hasOwnProperty.call(KIND_LABEL, kind)
      ? KIND_LABEL[kind]
      : KIND_OTHER;
  }

  function kindLabel(kind) {
    return t(kindKey(String(kind == null ? "" : kind)));
  }

  /** The word a click pushes into the search box for this group. */
  function kindQuery(kindKeyName) {
    return Object.prototype.hasOwnProperty.call(KIND_QUERY, kindKeyName)
      ? t(KIND_QUERY[kindKeyName])
      : t(kindKeyName);
  }

  /**
   * Group delta entries by their human label, preserving KIND_ORDER, then
   * payload order. Grouping by label rather than by raw kind is what merges
   * `service` and `service-image` into the one "services" column a reader
   * expects, instead of two columns with the same heading.
   */
  function groupDelta(entries) {
    var byKey = {};
    var firstKind = {};
    asArray(entries).forEach(function (e) {
      if (!e) return;
      var k = e.kind == null ? "" : String(e.kind);
      var lab = kindKey(k);
      if (!byKey[lab]) { byKey[lab] = []; firstKind[lab] = k; }
      byKey[lab].push(e.subject == null ? "" : String(e.subject));
    });

    var seen = {};
    var order = [];
    KIND_ORDER.forEach(function (k) {
      var lab = kindKey(k);
      if (byKey[lab] && !seen[lab]) { order.push(lab); seen[lab] = true; }
    });
    Object.keys(byKey).sort().forEach(function (lab) {
      if (!seen[lab]) order.push(lab);
    });

    var out = [];
    order.forEach(function (lab) {
      out.push({ kind: firstKind[lab], labelKey: lab, subjects: byKey[lab] });
    });
    return out;
  }

  /**
   * Copy a string and blink "copied" next to it. The clipboard API needs a
   * secure context, and a file:// page is not one in every browser, so a
   * failure here must not look like a broken click: the text is selected as a
   * fallback and the confirmation still appears.
   */
  function copyText(text, onDone) {
    var t = String(text == null ? "" : text);
    var nav = typeof navigator !== "undefined" ? navigator : null;
    var done = function (ok) { if (onDone) onDone(ok); };
    if (nav && nav.clipboard && nav.clipboard.writeText) {
      nav.clipboard.writeText(t).then(function () { done(true); }, function () { done(false); });
      return;
    }
    done(false);
  }

  /** The shared "copied" confirmation. One per host, cleared on a timer. */
  var copiedTimers = {};
  function blink(host, text) {
    if (!host) return;
    var key = host.id || (host.dataset && host.dataset.blinkKey) || "blink";
    var node = host.querySelector ? host.querySelector(".copied-mark") : null;
    if (!node) {
      node = el("span", "copied-mark", t("copy.done"));
      host.appendChild(node);
    }
    node.textContent = text || t("copy.done");
    node.hidden = false;
    window.clearTimeout(copiedTimers[key]);
    copiedTimers[key] = window.setTimeout(function () {
      node.hidden = true;
    }, 1200);
  }

  /* ========================================================== 4. view state == */

  var state = {
    payload: null,   // last scan payload, null before the first scan
    selected: 0,     // index into state.payload.groups
    filter: "all",   // "all" | "high" | "med" | "info"
    query: "",       // raw search box contents
    scanning: false,
    progress: [],    // { collector, elapsedMs, findingsAdded, error }
    saving: false,   // a save is in flight; the two header buttons are busy
    reportPath: ""   // last report path chosen, passed to remediation calls
  };

  var appInfo = null;
  var dom = {};

  function $(id) { return document.getElementById(id); }

  function cacheDom() {
    dom.version = $("app-version");
    dom.hostName = $("host-name");
    dom.hostUser = $("host-user");
    dom.elevChip = $("elev-chip");
    dom.scanBtn = $("scan-btn");
    dom.scanLabel = $("scan-label");
    dom.scanGlyph = $("scan-glyph");
    dom.counts = { high: $("count-high"), med: $("count-med"), info: $("count-info") };
    dom.headline = $("headline");
    dom.recWrap = $("rec-wrap");
    dom.recCount = $("rec-count");
    dom.recList = $("rec-list");
    dom.progress = $("progress");
    dom.progressSummary = $("progress-summary");
    dom.progressList = $("progress-list");
    dom.filters = document.querySelectorAll(".filter");
    dom.filterCounts = { all: $("f-all"), high: $("f-high"), med: $("f-med"), info: $("f-info") };
    dom.search = $("search");
    dom.groupList = $("group-list");
    dom.detailScroll = $("detail-scroll");
    dom.detailBody = $("detail-body");
    dom.warnCount = $("warn-count");
    dom.rawBtn = $("raw-btn");
    dom.rawCount = $("raw-count");
    dom.notProven = $("notproven");
    dom.drawer = $("drawer");
    dom.warnBlock = $("warn-block");
    dom.warnNote = $("warn-note");
    dom.warnList = $("warn-list");
    dom.rawSections = $("raw-sections");

    // "Since last time".
    dom.delta = $("delta");
    dom.deltaMark = $("delta-mark");
    dom.deltaSummary = $("delta-summary");
    dom.deltaChip = $("delta-chip");
    dom.deltaSince = $("delta-since");
    dom.deltaGroups = $("delta-groups");
    dom.deltaHint = $("delta-hint");

    // Save buttons.
    dom.saveTxtBtn = $("save-txt-btn");
    dom.saveJsonBtn = $("save-json-btn");

    // Containment.
    dom.detailActions = $("detail-actions");
  }

  /* ============================================================ 5. renderers == */

  /** A deliberate empty state. Never a blank pane, never a spinner. */
  function placeholder(title, lines) {
    var box = el("div", "placeholder");
    box.appendChild(el("h3", null, title));
    asArray(lines).forEach(function (l) {
      box.appendChild(el("p", l.charAt(0) === " " ? "hint" : null, l.trim()));
    });
    return box;
  }

  function renderHeader() {
    dom.version.textContent = appInfo && appInfo.version ? "v" + appInfo.version : "";

    var h = state.payload && state.payload.host;
    if (!h) {
      dom.hostName.textContent = t("host.none");
      dom.hostUser.textContent = "";
      dom.elevChip.textContent = t("elev.unknown");
      dom.elevChip.setAttribute("data-state", "unknown");
      dom.elevChip.title = t("elev.unknownTitle");
      return;
    }

    dom.hostName.textContent = h.name || t("host.unknownName");
    dom.hostUser.textContent = h.user || "";

    if (h.elevated === true) {
      dom.elevChip.textContent = t("elev.yes");
      dom.elevChip.setAttribute("data-state", "elevated");
      dom.elevChip.title = t("elev.yesTitle");
    } else {
      dom.elevChip.textContent = t("elev.no");
      dom.elevChip.setAttribute("data-state", "unelevated");
      dom.elevChip.title = t("elev.noTitle");
    }
  }

  function renderVerdict() {
    var v = state.payload && state.payload.verdict;
    var has = !!v;
    var groups = state.payload ? asArray(state.payload.groups) : [];
    var sums = tally(groups);

    // The three big numbers are the backend's verdict. Before a scan there is
    // nothing to count, and an em dash is honest about that.
    ["high", "med", "info"].forEach(function (s) {
      var n = has ? v[s] : null;
      dom.counts[s].textContent = typeof n === "number" ? String(n) : "\u2014";
    });

    ["all", "high", "med", "info"].forEach(function (s) {
      dom.filterCounts[s].textContent = has ? String(sums[s]) : "\u2014";
    });

    dom.headline.textContent = has
      ? (v.headline || "")
      : t("band.notRun");

    var recs = has ? asArray(v.recommendation) : [];
    dom.recWrap.hidden = recs.length === 0;
    dom.recCount.textContent = recs.length ? "(" + recs.length + ")" : "";
    clear(dom.recList);
    recs.forEach(function (r) { dom.recList.appendChild(el("li", null, r)); });

    // A tooltip is a sentence too. The labels come from t() and the values are
    // the backend's, which stay as they are; the separator is the same middle
    // dot in both languages.
    var h = state.payload && state.payload.host;
    var parts = [];
    if (h) {
      if (h.os) parts.push(h.os + (h.build ? " " + t("cover.build", { build: h.build }) : ""));
      if (h.installDate) parts.push(t("cover.installed", { at: h.installDate }));
      if (h.bootTime) parts.push(t("cover.booted", { at: h.bootTime }));
      if (h.collectedAt) parts.push(t("cover.scanned", { at: h.collectedAt }));
      if (typeof h.scannedInMs === "number") parts.push(h.scannedInMs + " ms");
    }
    if (parts.length) dom.headline.title = parts.join(" \u00B7 ");
    else dom.headline.removeAttribute("title");
  }

  /**
   * The "since last time" strip. Three deliberate states, one reserved box:
   *   - no scan yet, or the backend sent no delta: idle, barely there.
   *   - a first run: one quiet line, no empty lists.
   *   - a later run with nothing changed: the quietest line this design makes.
   *   - a later run with changes: the backend's summary, then the entries,
   *     grouped by kind in human words. newPresence is the case worth noticing,
   *     so it gets the loudest ink on the screen and a chip.
   */
  function renderDelta() {
    var d = state.payload && state.payload.delta;
    clear(dom.deltaGroups);
    dom.deltaChip.hidden = true;
    dom.deltaSince.textContent = "";
    dom.deltaMark.textContent = "";
    dom.deltaHint.hidden = false;

    dom.deltaChip.title = t("delta.chipTitle");

    if (!d) {
      dom.delta.setAttribute("data-state", "idle");
      if (!state.payload) {
        dom.deltaSummary.textContent = t("delta.idle");
      } else if (asArray(state.payload.groups).length === 0 &&
                 asArray(state.payload.warnings).length > 0) {
        dom.deltaSummary.textContent = t("delta.idleIncomplete");
      } else {
        dom.deltaSummary.textContent = t("delta.idleNone");
      }
      dom.deltaHint.hidden = true;
      return;
    }

    // A first run is a fact about the machine, not a measurement of change.
    if (d.firstRun) {
      dom.delta.setAttribute("data-state", "quiet");
      dom.deltaMark.textContent = "\u25CB";
      dom.deltaSummary.textContent = t("delta.first");
      dom.deltaHint.hidden = true;
      return;
    }

    var added = asArray(d.added);
    var removed = asArray(d.removed);

    if (added.length === 0 && removed.length === 0) {
      dom.delta.setAttribute("data-state", "quiet");
      dom.deltaMark.textContent = "\u25CB";
      // The timestamp belongs in the sentence here, so it is not repeated in
      // the right-hand gutter.
      dom.deltaSummary.textContent = d.since
        ? t("delta.quiet", { since: d.since })
        : t("delta.quietNoTime");
      dom.deltaHint.hidden = true;
      return;
    }

    // Something changed. newPresence raises the whole strip to the loudest ink.
    dom.deltaSince.textContent = d.since ? t("delta.since", { since: d.since }) : "";
    var loud = d.newPresence === true;
    dom.delta.setAttribute("data-state", "loud");
    dom.deltaMark.textContent = loud ? "\u25CF" : "\u25D0";
    // The count sentence is built here rather than printed from the backend:
    // this line is a sentence a person reads, and the core's own summary is
    // English prose. The numbers are still the core's numbers.
    dom.deltaSummary.textContent =
      t("delta.counts", { n: added.length, m: removed.length });
    dom.deltaChip.hidden = !loud;

    // One column per kind, added first then removed, capped per group.
    renderDeltaColumn("added", added);
    renderDeltaColumn("removed", removed);
  }

  /** One group of entries per kind, with the +/- marker in the gutter. */
  function renderDeltaColumn(op, entries) {
    var groups = groupDelta(entries);
    groups.forEach(function (grp) {
      var box = el("div", "delta-group");
      var head = el("div", "delta-group-head");
      // The group label is the one click that narrows the finding list to this
      // kind: it pushes the human word into the existing search box, so the
      // filter machinery below is reused rather than duplicated.
      var labelBtn = el("button", "delta-group-label");
      labelBtn.type = "button";
      labelBtn.appendChild(el("span", "micro", t(grp.labelKey)));
      labelBtn.title = t("delta.groupTitle", { label: t(grp.labelKey) });
      labelBtn.addEventListener("click", function () { filterToKind(grp.labelKey); });
      head.appendChild(labelBtn);
      head.appendChild(el("span", "delta-group-n", String(grp.subjects.length)));
      box.appendChild(head);

      var ul = el("ul", "delta-entries");
      var shown = grp.subjects.slice(0, MAX_PER_GROUP);
      shown.forEach(function (subject) {
        ul.appendChild(deltaEntry(op, grp.kind, subject));
      });
      box.appendChild(ul);

      if (grp.subjects.length > MAX_PER_GROUP) {
        box.appendChild(el("div", "delta-more",
          t("delta.more", { n: grp.subjects.length - MAX_PER_GROUP })));
      }
      dom.deltaGroups.appendChild(box);
    });
  }

  /** A clickable entry: a button so it is keyboard reachable, copying its subject. */
  function deltaEntry(op, kind, subject) {
    var li = el("li");
    var btn = el("button", "delta-entry");
    btn.type = "button";
    btn.setAttribute("data-op", op);
    btn.setAttribute("data-kind", kind);
    btn.appendChild(el("span", "delta-sign", op === "added" ? "+" : "\u2212"));
    btn.appendChild(el("span", "delta-subject",
      subject === "" ? t("delta.empty") : subject));
    btn.title = subject === ""
      ? t("delta.copyTitleEmpty")
      : t("delta.copyTitle", { subject: subject });
    btn.addEventListener("click", function () {
      copyText(subject, function () {
        blink(btn.parentNode ? btn.parentNode : btn, t("copy.done"));
      });
    });
    li.appendChild(btn);
    return li;
  }

  /**
   * Narrow the finding list to a delta kind. This is a search query, not a new
   * filter mode: the existing box, the existing match, and the existing Esc
   * behaviour all apply, and a reviewer sees why the list emptied.
   */
  function filterToKind(labelKey) {
    var q = kindQuery(labelKey);
    dom.search.value = q;
    state.query = q;
    var rows = visibleGroups();
    if (rows.length > 0) state.selected = rows[0].index;
    renderList();
    renderDetail();
    renderActions();
    if (rows.length === 0) {
      // Nothing matched: say so once, in the strip, rather than leaving the
      // user wondering which click emptied the list.
      dom.deltaHint.hidden = false;
      dom.deltaHint.textContent =
        t("delta.hintMiss", { label: t(labelKey) });
      window.clearTimeout(copiedTimers.deltaHint);
      copiedTimers.deltaHint = window.setTimeout(function () {
        dom.deltaHint.textContent = t("delta.hint");
      }, 2000);
    }
  }

  function renderProgress() {
    var active = state.scanning || state.progress.length > 0;
    dom.progress.hidden = !active;
    if (!active) {
      clear(dom.progressList);
      return;
    }

    dom.progressSummary.textContent = state.scanning
      ? t("progress.reported", { n: state.progress.length })
      : t("progress.finished", { n: state.progress.length });

    clear(dom.progressList);
    state.progress.forEach(function (p) {
      var li = el("li", p.error ? "is-bad" : null);
      // The collector identifier is the core's name for the collector and stays
      // Latin, both on screen and in a log someone greps. The Russian word is
      // attached to it as a tooltip: the line stays narrow, the reader still
      // gets the word.
      var nameNode = el("span", "prog-name",
        p.collector == null ? t("progress.unnamed") : p.collector);
      if (p.collector != null) {
        nameNode.title = t("collector." + String(p.collector));
      }
      li.appendChild(nameNode);
      li.appendChild(el("span", "prog-ms",
        typeof p.elapsedMs === "number" ? p.elapsedMs + " ms" : "\u2014"));
      li.appendChild(el("span", "prog-added",
        typeof p.findingsAdded === "number" ? String(p.findingsAdded) : "\u2014"));
      li.appendChild(el("span", "prog-note", p.error ? "! " + p.error : ""));
      dom.progressList.appendChild(li);
    });
    dom.progressList.scrollTop = dom.progressList.scrollHeight;
  }

  /** Groups surviving the severity filter and the search box, in payload order. */
  function visibleGroups() {
    var groups = state.payload ? asArray(state.payload.groups) : [];
    var q = state.query.trim().toLowerCase();
    var out = [];
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i] || {};
      if (state.filter !== "all" && g.severity !== state.filter) continue;
      if (q && searchText(g).indexOf(q) === -1) continue;
      out.push({ index: i, group: g });
    }
    return out;
  }

  function renderList() {
    var rows = visibleGroups();
    clear(dom.groupList);
    dom.groupList.setAttribute("aria-activedescendant", "");

    if (!state.payload) {
      var box = el("li");
      box.appendChild(placeholder(t("list.emptyTitle"), [
        t("list.empty1"),
        t("list.empty2")
      ]));
      dom.groupList.appendChild(box);
      return;
    }

    if (rows.length === 0) {
      var total = asArray(state.payload.groups).length;
      var li = el("li");
      var warns = asArray(state.payload.warnings).length;
      if (total === 0 && warns > 0) {
        // Zero groups plus failed collectors is not a clean machine, and it must
        // never read as one: the warnings are the finding here.
        li.appendChild(placeholder(t("list.incompleteTitle"), [
          t("list.incomplete1", { n: warns }),
          t("list.incomplete2")
        ]));
      } else if (total === 0) {
        li.appendChild(placeholder(t("list.cleanTitle"), [
          t("list.clean1"),
          t("list.clean2")
        ]));
      } else {
        li.appendChild(placeholder(t("list.noMatchTitle"), [
          t("list.noMatch1", { n: total }),
          t("list.noMatch2")
        ]));
      }
      dom.groupList.appendChild(li);
      return;
    }

    rows.forEach(function (r) {
      var g = r.group;
      var sev = SEVERITY_ORDER[g.severity] === undefined ? "info" : g.severity;
      var li = el("li", "group-row" + (r.index === state.selected ? " is-sel" : ""));
      li.setAttribute("data-sev", sev);
      li.setAttribute("data-index", String(r.index));
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", r.index === state.selected ? "true" : "false");
      li.id = "grp-" + r.index;

      li.appendChild(el("span", "row-glyph glyph", glyph(sev)));

      var main = el("div", "row-main");
      var top = el("div", "row-top");
      top.appendChild(el("span", "sev-tag", label(sev)));
      top.appendChild(el("span", "row-title",
        g.title == null ? t("row.untitled") : g.title));
      main.appendChild(top);

      var meta = el("div", "row-meta");
      meta.appendChild(el("span", "row-cat", g.category == null ? "" : g.category));
      if (typeof g.instances === "number" && g.instances > 1) {
        meta.appendChild(el("span", "row-instances",
          t("row.instances", { n: g.instances })));
      }
      main.appendChild(meta);
      li.appendChild(main);

      dom.groupList.appendChild(li);
      if (r.index === state.selected) {
        dom.groupList.setAttribute("aria-activedescendant", li.id);
      }
    });
  }

  function renderDetail() {
    clear(dom.detailBody);

    if (!state.payload) {
      dom.detailBody.appendChild(placeholder(t("detail.noScanTitle"), [
        t("detail.noScan1"),
        t("detail.noScan2")
      ]));
      return;
    }

    if (asArray(state.payload.groups).length === 0) {
      var wcount = asArray(state.payload.warnings).length;
      if (wcount > 0) {
        dom.detailBody.appendChild(placeholder(t("detail.incompleteTitle"), [
          t("detail.incomplete1", { n: wcount }),
          t("detail.incomplete2")
        ]));
      } else {
        dom.detailBody.appendChild(placeholder(t("detail.cleanTitle"), [
          t("detail.clean1"),
          t("detail.clean2")
        ]));
      }
      return;
    }

    var rows = visibleGroups();
    var current = null;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].index === state.selected) { current = rows[i]; break; }
    }
    if (!current) {
      dom.detailBody.appendChild(placeholder(t("detail.hiddenTitle"), [
        t("detail.hidden1"),
        t("detail.hidden2")
      ]));
      return;
    }

    var g = current.group;
    var sev = SEVERITY_ORDER[g.severity] === undefined ? "info" : g.severity;

    var head = el("div", "detail-head");
    head.appendChild(el("h2", "detail-title",
      g.title == null ? t("row.untitled") : g.title));
    var meta = el("div", "detail-meta");
    meta.appendChild(el("span", "sev-tag", label(sev)));
    meta.appendChild(el("span", "detail-cat", g.category == null ? "" : g.category));
    if (typeof g.instances === "number" && g.instances > 1) {
      meta.appendChild(el("span", "instances",
        t("detail.instances", { n: g.instances })));
    }
    head.appendChild(meta);
    dom.detailBody.appendChild(head);

    var ev = asArray(g.evidence);
    var evSec = el("section", "detail-sec");
    evSec.appendChild(el("h3", "micro", t("detail.evidence")));
    if (ev.length === 0) {
      evSec.appendChild(el("p", null, t("detail.noEvidence")));
    } else {
      var ul = el("ul", "evidence-lines");
      ev.forEach(function (line, n) {
        var li = el("li");
        li.appendChild(el("span", "ev-gutter", String(n + 1)));
        li.appendChild(el("span", "ev-text", line));
        ul.appendChild(li);
      });
      evSec.appendChild(ul);
    }
    dom.detailBody.appendChild(evSec);

    var rem = asArray(g.remediation);
    if (rem.length > 0) {
      var remSec = el("section", "detail-sec");
      remSec.appendChild(el("h3", "micro", t("detail.remediation")));
      var rul = el("ul", "remediation-lines");
      rem.forEach(function (line) {
        var li = el("li");
        li.appendChild(el("span", "arrow", "->"));
        li.appendChild(el("span", "rem-text", line));
        rul.appendChild(li);
      });
      remSec.appendChild(rul);
      dom.detailBody.appendChild(remSec);
    }

    dom.detailScroll.scrollTop = 0;
  }

  /**
   * Evidence heuristics for the containment forms. These are guesses about
   * where a name is in a line, not decisions about what is suspicious - a wrong
   * guess only changes a prefill, and the user edits it before confirming.
   */

  /** A service name as it appears in a service evidence line: `name=AcmeSupportSvc ...`. */
  function guessServiceName(evidence) {
    var lines = asArray(evidence);
    for (var i = 0; i < lines.length; i++) {
      var m = /(?:^|[\s;])name=([^\s"]+)/.exec(String(lines[i]));
      if (m) return m[1];
      m = /(?:^|[\s;])service=([^\s"]+)/.exec(String(lines[i]));
      if (m) return m[1];
    }
    // Fall back to the first token of the first name= line's quoted display.
    return "";
  }

  /**
   * A Run / RunOnce key path in the evidence, split into hive, key and value.
   * The two shapes the collectors emit are `...\Run\Value = ...` and
   * `...\Run: Value = ...`, so the separator before the value is either a
   * backslash or a colon and is not part of the value.
   */
  function guessAutostart(evidence) {
    var lines = asArray(evidence);
    for (var i = 0; i < lines.length; i++) {
      var s = String(lines[i]);
      var m = /(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\([^\r\n]*?(?:RunOnce|Run))\s*[:\\]\s*([^\s"\\=]+)/
        .exec(s);
      if (m) {
        var value = m[3].replace(/^[:\\]+/, "");
        if (value) return { hive: m[1], key: m[2], value: value };
      }
    }
    return null;
  }

  /**
   * What, if anything, a containment action can name for this finding.
   *
   * The test is a real identifier in the evidence, not the word "service" in
   * prose. The HIGH finding's own evidence says it is "not referenced by any
   * service", and offering a Disable-service form because of that sentence
   * would put the wrong control in front of the most alarming finding here.
   */
  function actionKinds(g) {
    return {
      service: guessServiceName(g.evidence) !== "",
      autostart: guessAutostart(g.evidence) !== null
    };
  }

  /**
   * The containment panel. Shown only when at least one action can name its
   * target from the finding - an empty form is worse than no form. Each action
   * carries a one-line consequence sentence, a Confirm box that must be ticked
   * before its button enables, and a result line that holds both the success
   * text and a returned Err message. Never a dialog.
   */
  function renderActions() {
    clear(dom.detailActions);
    dom.detailActions.hidden = true;

    if (!state.payload) return;

    var rows = visibleGroups();
    var current = null;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].index === state.selected) { current = rows[i]; break; }
    }
    if (!current) return;

    var g = current.group;
    var kinds = actionKinds(g);
    if (!kinds.service && !kinds.autostart) return;

    var head = el("div", "actions-head");
    head.appendChild(el("h3", "micro actions-title", t("actions.title")));
    head.appendChild(el("span", "delta-group-n", t("actions.confirmNote")));
    dom.detailActions.appendChild(head);
    dom.detailActions.appendChild(el("p", "actions-note", t("actions.note")));

    if (kinds.service) {
      dom.detailActions.appendChild(serviceForm(g));
    }
    if (kinds.autostart) {
      dom.detailActions.appendChild(autostartForm(g));
    }
    dom.detailActions.hidden = false;
  }

  /** Wire a form's Confirm box to its button: the button enables only when ticked. */
  function confirmGate(checkbox, button, check) {
    checkbox.addEventListener("change", function () {
      button.disabled = !checkbox.checked;
    });
    button.disabled = !checkbox.checked;
    if (typeof check === "function") {
      button.addEventListener("click", check);
    }
  }

  function resultLine(host) {
    var p = el("p", "action-result");
    p.hidden = true;
    host.appendChild(p);
    return p;
  }

  function showResult(p, op, text, lead) {
    clear(p);
    if (lead) p.appendChild(el("span", "action-result-lead", lead));
    p.appendChild(el("span", null, text));
    p.setAttribute("data-op", op);
    p.hidden = false;
  }

  function field(labelText, value, wide, placeholder) {
    var wrap = el("label", "action-field" + (wide ? " wide" : ""));
    wrap.appendChild(el("span", null, labelText));
    var input = el("input");
    input.type = "text";
    input.value = value == null ? "" : String(value);
    if (placeholder) input.placeholder = placeholder;
    input.autocomplete = "off";
    input.spellcheck = false;
    wrap.appendChild(input);
    wrap.input = input;
    return wrap;
  }

  function serviceForm(g) {
    var form = el("div", "action-form");
    form.appendChild(el("div", "action-name", t("actions.service")));
    form.appendChild(el("p", "action-consequence",
      t("actions.serviceConsequence")));

    var fields = el("div", "action-fields");
    var nameField = field(t("actions.serviceField"), guessServiceName(g.evidence), true,
      t("actions.servicePlaceholder"));
    fields.appendChild(nameField);
    form.appendChild(fields);

    var result = resultLine(form);

    var row = el("div", "action-row");
    var cb = el("input"); cb.type = "checkbox";
    var lab = el("label", "action-confirm");
    lab.appendChild(cb);
    lab.appendChild(el("span", null, t("actions.confirm")));
    var btn = el("button", "action-go", t("actions.service"));
    btn.type = "button";
    row.appendChild(lab);
    row.appendChild(btn);
    form.appendChild(row);

    confirmGate(cb, btn, function () {
      var name = nameField.input.value.trim();
      if (!name) {
        showResult(result, "err", t("actions.serviceRequired"));
        return;
      }
      btn.disabled = true;
      showResult(result, "busy", t("actions.working"));
      Backend.invoke("disable_service", { name: name, reportPath: reportPathFor() })
        .then(function (res) {
          reportOutcome(result, res);
        })
        .catch(function (err) {
          // Err(string) is the normal answer for a name that is not here. Its
          // own text is the core's and stays in whatever language the core used;
          // only this label around it is translated.
          showResult(result, "err", describeError(err), t("actions.notDone"));
        })
        .then(function () { btn.disabled = !cb.checked; });
    });
    return form;
  }

  function autostartForm(g) {
    var form = el("div", "action-form");
    form.appendChild(el("div", "action-name", t("actions.autostart")));
    form.appendChild(el("p", "action-consequence",
      t("actions.autostartConsequence")));

    var guess = guessAutostart(g.evidence) || { hive: "", key: "", value: "" };
    var fields = el("div", "action-fields");
    var hiveField = field(t("actions.hiveField"), guess.hive, false, "HKCU");
    var keyField = field(t("actions.keyField"), guess.key, true,
      t("actions.keyPlaceholder"));
    var valueField = field(t("actions.valueField"), guess.value, false, "AcmeAgent");
    fields.appendChild(hiveField);
    fields.appendChild(keyField);
    fields.appendChild(valueField);
    form.appendChild(fields);

    var result = resultLine(form);

    var row = el("div", "action-row");
    var cb = el("input"); cb.type = "checkbox";
    var lab = el("label", "action-confirm");
    lab.appendChild(cb);
    lab.appendChild(el("span", null, t("actions.confirm")));
    var btn = el("button", "action-go", t("actions.autostart"));
    btn.type = "button";
    row.appendChild(lab);
    row.appendChild(btn);
    form.appendChild(row);

    confirmGate(cb, btn, function () {
      var hive = hiveField.input.value.trim();
      var key = keyField.input.value.trim();
      var value = valueField.input.value.trim();
      if (!hive || !key || !value) {
        showResult(result, "err", t("actions.autostartRequired"));
        return;
      }
      btn.disabled = true;
      showResult(result, "busy", t("actions.working"));
      Backend.invoke("remove_autostart", { hive: hive, key: key, value: value, reportPath: reportPathFor() })
        .then(function (res) {
          reportOutcome(result, res);
        })
        .catch(function (err) {
          showResult(result, "err", describeError(err), t("actions.notDone"));
        })
        .then(function () { btn.disabled = !cb.checked; });
    });
    return form;
  }

  /** Success line: the backend's outcome, then where the undo record went. */
  function reportOutcome(result, res) {
    var r = res || {};
    clear(result);
    // The backend's own outcome sentence is data and is printed as it came: it
    // is the record of what actually happened to this machine, and a second
    // translation of it would be a claim this file has no standing to make.
    if (r.outcome == null) {
      result.appendChild(el("span", "action-result-lead", t("actions.doneNoOutcome")));
    } else {
      result.appendChild(el("span", "action-result-lead", t("actions.doneLabel")));
      result.appendChild(el("span", null, String(r.outcome)));
    }
    if (r.undoPath) {
      result.appendChild(el("span", null, "  " + t("actions.undo", { path: String(r.undoPath) })));
    }
    result.setAttribute("data-op", "ok");
    result.hidden = false;
  }

  /** The last report path the user chose, if any, to pass to a remediation call.
   *  The backend writes a fresh undo record next to it; an empty string means
   *  the shell keeps the undo record wherever it normally does. */
  function reportPathFor() {
    return state.reportPath || "";
  }

  function renderWarnings() {
    var has = !!state.payload;
    var warnings = has ? asArray(state.payload.warnings) : [];
    clear(dom.warnList);

    if (!has) {
      dom.warnNote.textContent = "";
      dom.warnList.appendChild(el("li", "warn-note", t("warn.none")));
      return;
    }
    if (warnings.length === 0) {
      dom.warnNote.textContent = "";
      dom.warnList.appendChild(el("li", "warn-note", t("warn.clean")));
      return;
    }
    dom.warnNote.textContent = t("warn.note");
    warnings.forEach(function (w) {
      var li = el("li");
      li.appendChild(el("span", "glyph", "!"));
      li.appendChild(el("span", "warn-text", w));
      dom.warnList.appendChild(li);
    });
  }

  function renderRaw() {
    var has = !!state.payload;
    var sections = has ? asArray(state.payload.raw) : [];
    clear(dom.rawSections);

    if (!has) {
      dom.rawSections.appendChild(placeholder(t("raw.noneTitle"), [
        t("raw.none1")
      ]));
      return;
    }
    if (sections.length === 0) {
      dom.rawSections.appendChild(placeholder(t("raw.noSectionsTitle"), [
        t("raw.noSections1")
      ]));
      return;
    }

    sections.forEach(function (s, i) {
      var det = el("details", "raw-sec");
      if (i === 0) det.open = true;

      var lines = asArray(s.lines);
      var sum = el("summary");
      // A raw section heading is the collector\u2019s own name and is shown as it
      // came: it is the string a reader will search the report for.
      sum.appendChild(el("span", "micro",
        s.section == null ? t("raw.unnamed") : s.section));
      sum.appendChild(el("span", "raw-lines-n", t("raw.lines", { n: lines.length })));
      det.appendChild(sum);

      var ul = el("ul", "raw-lines");
      if (lines.length === 0) {
        var empty = el("li");
        empty.appendChild(el("span", "raw-n", ""));
        empty.appendChild(el("span", "raw-t", t("raw.empty")));
        ul.appendChild(empty);
      } else {
        lines.forEach(function (line, n) {
          var li = el("li");
          li.appendChild(el("span", "raw-n", String(n + 1)));
          li.appendChild(el("span", "raw-t", line));
          ul.appendChild(li);
        });
      }
      det.appendChild(ul);
      dom.rawSections.appendChild(det);
    });
  }

  function renderFooter() {
    var has = !!state.payload;
    var warnings = has ? asArray(state.payload.warnings) : [];
    var raw = has ? asArray(state.payload.raw) : [];

    var rawLines = 0;
    raw.forEach(function (s) { rawLines += asArray(s.lines).length; });

    dom.warnCount.textContent = has ? String(warnings.length) : "\u2014";
    dom.warnCount.className = "footer-count" + (has && warnings.length === 0 ? " is-zero" : "");
    dom.rawCount.textContent = has
      ? t("raw.count", { n: raw.length, m: rawLines })
      : "";

    // The "what this does not prove" text is always on screen, never behind a
    // click. Prefer the backend's own wording; fall back to the identical
    // sentence from the core's console footer rather than inventing a weaker one.
    if (has && state.payload.notProven) {
      // The core speaks for itself here and its sentence is the sharper one.
      // When this file has to say it, it says the same thing from t(): the claim
      // is the whole point of the line, so a translated fallback that dropped it
      // would be worse than no line at all.
      dom.notProven.textContent = state.payload.notProven;
    } else if (has) {
      dom.notProven.textContent = t("foot.notProven");
    } else {
      dom.notProven.textContent = t("foot.notRun");
    }

    renderWarnings();
    renderRaw();
  }

  function syncFilterButtons() {
    for (var i = 0; i < dom.filters.length; i++) {
      var b = dom.filters[i];
      var on = b.getAttribute("data-filter") === state.filter;
      b.classList.toggle("is-on", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    }
  }

  /* ========================================================== 5b. saving == */

  /** irscan-<host>-<stamp>.txt. The stamp is filesystem-safe: no colons. */
  function defaultReportPath(format) {
    var h = (state.payload && state.payload.host && state.payload.host.name) || "host";
    var safeHost = String(h).replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "host";
    var now = new Date();
    var stamp = now.getFullYear() + String(now.getMonth() + 1).padStart(2, "0") +
      String(now.getDate()).padStart(2, "0") + "-" +
      String(now.getHours()).padStart(2, "0") +
      String(now.getMinutes()).padStart(2, "0");
    return "irscan-" + safeHost + "-" + stamp + (format === "json" ? ".json" : ".txt");
  }

  function setSaving(on) {
    state.saving = on;
    var has = !!state.payload;
    dom.saveTxtBtn.disabled = on || !has;
    dom.saveJsonBtn.disabled = on || !has;
    dom.saveTxtBtn.setAttribute("aria-busy", on ? "true" : "false");
  }

  /**
   * Save the report. In a shell the path comes from the dialog plugin. Without
   * one (browser, demo) a path input appears in the header the first time a
   * save is attempted, and the button reads it from then on - so a design
   * review can still press this, and the second press still means something.
   * A cancel in a real dialog is not an error: nothing happens, nothing is said.
   */
  function saveReport(format) {
    if (state.saving || !state.payload) return;

    // Format names belong to the operating system's file dialog, not to the
    // report: they are the dialog's own vocabulary and stay Latin, so that a
    // user looking at a native picker sees the words the picker itself uses.
    var opts = {
      defaultPath: defaultReportPath(format),
      filters: format === "json"
        ? [{ name: "JSON", extensions: ["json"] }, { name: "All files", extensions: ["*"] }]
        : [{ name: "Text", extensions: ["txt"] }, { name: "All files", extensions: ["*"] }]
    };

    Backend.save(opts).then(function (chosen) {
      if (chosen) return chosen;
      if (Backend.hasDialog()) return null;   // cancelled in a real dialog
      return askPathFallback(opts.defaultPath, format);
    }).then(function (path) {
      if (!path) return null;                 // cancelled: say nothing
      state.reportPath = path;
      setSaving(true);
      return Backend.invoke("export_report", {
        format: format,
        path: path,
        cursor: state.payload ? state.payload.cursor : null
      }).then(function (written) {
        var where = written == null ? path : String(written);
        showSaveConfirmation(where);
        setSaving(false);
      }, function (err) {
        showSaveConfirmation(t("save.fail", { message: describeError(err) }), true);
        setSaving(false);
      });
    });
  }

  /**
   * Inline path control for the no-dialog case. The first save reveals it and
   * fills it with the suggested name; the save then proceeds with that name.
   * From the second save on, the box stays and its contents are used, so the
   * button means "save where I said" rather than "open a box".
   */
  function askPathFallback(defaultPath, format) {
    var wrap = document.getElementById("save-path-wrap");
    if (!wrap) {
      wrap = el("label", "action-field wide save-path");
      wrap.id = "save-path-wrap";
      wrap.appendChild(el("span", null, t("save.as")));
      var input = el("input");
      input.type = "text";
      input.value = defaultPath;
      input.autocomplete = "off";
      input.spellcheck = false;
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { e.preventDefault(); saveReport(format); }
      });
      wrap.appendChild(input);
      // Anchored over the host line rather than inserted into the button row:
      // appearing must not move the host name, the buttons, or the panes.
      document.querySelector(".topbar").appendChild(wrap);
      wrap.input = input;
      window.setTimeout(function () { input.focus(); input.select(); }, 0);
      return Promise.resolve(defaultPath);
    }
    return Promise.resolve(wrap.input.value.trim() || defaultPath);
  }

  /** The "copied"-style confirmation: a path, shown briefly, next to the buttons. */
  function showSaveConfirmation(text, bad) {
    var host = document.querySelector(".topbar");
    var node = document.getElementById("save-confirm");
    if (!node) {
      node = el("span", "copied-mark save-confirm");
      node.id = "save-confirm";
      node.setAttribute("data-op", bad ? "err" : "ok");
      host.appendChild(node);
    }
    node.textContent = bad ? text : t("save.ok", { path: text });
    node.hidden = false;
    window.clearTimeout(copiedTimers.save);
    copiedTimers.save = window.setTimeout(function () { node.hidden = true; }, 2600);
  }

  /** Enable/disable the header buttons as data arrives. Called from render(). */
  function renderSave() {
    var has = !!state.payload;
    dom.saveTxtBtn.disabled = state.saving || !has;
    dom.saveJsonBtn.disabled = state.saving || !has;
  }

  /** One entry point: no renderer assumes another has already run. */
  function render() {
    renderHeader();
    renderVerdict();
    renderDelta();
    renderProgress();
    renderList();
    renderDetail();
    renderActions();
    renderFooter();
    renderSave();
    syncFilterButtons();
  }

  /* =========================================================== 6. behaviour == */

  function selectIndex(index) {
    var groups = state.payload ? asArray(state.payload.groups) : [];
    if (index < 0 || index >= groups.length) return;
    state.selected = index;

    renderList();
    renderDetail();
    renderActions();

    var row = dom.groupList.querySelector('.group-row[data-index="' + index + '"]');
    if (row && row.scrollIntoView) row.scrollIntoView({ block: "nearest" });
  }

  /** j / k walk the visible rows, not the payload, so the filter is respected. */
  function stepSelection(delta) {
    var rows = visibleGroups();
    if (rows.length === 0) return;

    var at = -1;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].index === state.selected) { at = i; break; }
    }
    var next = at < 0
      ? (delta > 0 ? 0 : rows.length - 1)
      : Math.min(rows.length - 1, Math.max(0, at + delta));
    selectIndex(rows[next].index);
  }

  function setFilter(f) {
    if (["all", "high", "med", "info"].indexOf(f) === -1) return;
    state.filter = f;

    var groups = state.payload ? asArray(state.payload.groups) : [];
    var stillVisible = false;
    if (groups[state.selected] && (f === "all" || groups[state.selected].severity === f)) {
      stillVisible = true;
    }
    if (!stillVisible) {
      var rows = visibleGroups();
      if (rows.length > 0) state.selected = rows[0].index;
    }

    renderList();
    renderDetail();
    syncFilterButtons();
  }

  function onSearchInput() {
    state.query = dom.search.value;

    var rows = visibleGroups();
    var found = false;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].index === state.selected) { found = true; break; }
    }
    if (!found && rows.length > 0) state.selected = rows[0].index;

    renderList();
    renderDetail();
  }

  var searchTimer = null;

  function onSearchKey(e) {
    // Esc while typing clears the box and keeps the filter intact.
    if (e.key === "Escape") {
      e.preventDefault();
      dom.search.value = "";
      onSearchInput();
      dom.search.blur();
    }
  }

  function isTypingTarget(t) {
    if (!t) return false;
    var tag = t.tagName ? t.tagName.toLowerCase() : "";
    return tag === "input" || tag === "textarea" || tag === "select" || t.isContentEditable === true;
  }

  function onGlobalKey(e) {
    if (isTypingTarget(e.target)) return;

    if (e.key === "/") {
      e.preventDefault();
      dom.search.focus();
      dom.search.select();
      return;
    }
    if (e.key === "j" || e.key === "J") { e.preventDefault(); stepSelection(1); return; }
    if (e.key === "k" || e.key === "K") { e.preventDefault(); stepSelection(-1); return; }
    // `d` jumps to the delta strip and reads it out with a focus ring. It is the
    // one key for "what changed", which is the question this screen answers first.
    if (e.key === "d" || e.key === "D") {
      e.preventDefault();
      jumpToDelta();
      return;
    }
    if (e.key === "Escape" && state.query) {
      e.preventDefault();
      dom.search.value = "";
      onSearchInput();
    }
  }

  /** Focus the delta strip, and say what it holds so a screen reader gets it too. */
  function jumpToDelta() {
    if (dom.delta && dom.delta.focus) dom.delta.focus();
    var node = dom.deltaSummary;
    if (node && node.scrollIntoView) node.scrollIntoView({ block: "nearest" });
  }

  function setScanning(on) {
    state.scanning = on;
    dom.scanBtn.disabled = on;
    dom.scanBtn.classList.toggle("is-busy", on);
    dom.scanLabel.textContent = on ? t("scan.busy") : t("scan.button");
    dom.scanBtn.setAttribute("aria-busy", on ? "true" : "false");
  }

  function runScan() {
    if (state.scanning) return;

    state.progress = [];
    state.selected = 0;
    setScanning(true);
    renderProgress();
    // A new run invalidates the previous report path: the undo records of the
    // old run belong to the old report.
    state.reportPath = "";

    var done = false;
    var finish = function () {
      if (done) return;
      done = true;
      setScanning(false);
      render();
    };

    Backend.invoke("scan", { quick: false }).then(function (payload) {
      state.payload = payload || null;
      finish();
    }).catch(function (err) {
      state.payload = {
        host: null,
        verdict: {
          high: 0, med: 0, info: 0,
          headline: LANG === "ru"
            ? "Проверка не завершилась: " + describeError(err)
            : "The scan did not complete: " + describeError(err),
          recommendation: []
        },
        groups: [],
        warnings: ["scan: " + describeError(err)],
        raw: [],
        notProven: "",
        // A run that failed changed nothing and proves nothing: an empty delta
        // would read as the quiet state, which is a claim this run cannot make.
        delta: null
      };
      // A failed run is a result too: the warning list carries the reason, and
      // the verdict band must not look like a clean machine.
      state.payload.host = state.payload.host ||
        { name: t("progress.unnamed"), user: "", elevated: false };
      finish();
    });
  }

  function describeError(err) {
    if (!err) return t("err.unknown");
    if (typeof err === "string") return err;
    return err.message || String(err);
  }

  function wire() {
    dom.scanBtn.addEventListener("click", runScan);
    dom.saveTxtBtn.addEventListener("click", function () { saveReport("txt"); });
    dom.saveJsonBtn.addEventListener("click", function () { saveReport("json"); });

    for (var i = 0; i < dom.filters.length; i++) {
      (function (btn) {
        btn.addEventListener("click", function () {
          setFilter(btn.getAttribute("data-filter"));
        });
      }(dom.filters[i]));
    }

    dom.search.addEventListener("input", function () {
      // Typing is cheap here, but the debounce keeps a large payload smooth.
      window.clearTimeout(searchTimer);
      searchTimer = window.setTimeout(onSearchInput, 60);
    });
    dom.search.addEventListener("keydown", onSearchKey);

    dom.groupList.addEventListener("click", function (e) {
      var node = e.target;
      while (node && node !== dom.groupList) {
        if (node.classList && node.classList.contains("group-row")) {
          selectIndex(parseInt(node.getAttribute("data-index"), 10));
          return;
        }
        node = node.parentNode;
      }
    });

    dom.rawBtn.addEventListener("click", function () {
      var open = dom.drawer.hidden;
      dom.drawer.hidden = !open;
      dom.rawBtn.setAttribute("aria-expanded", open ? "true" : "false");
      dom.drawer.scrollIntoView({ block: "end" });
    });

    document.addEventListener("keydown", onGlobalKey);
  }

  /* =============================================================== 7. boot == */

  function boot() {
    // The markup is filled from the dictionary before anything is cached or
    // rendered: the language decision has one home, and it happens once.
    applyI18n(document);
    cacheDom();
    wire();
    // The button label is renderer-owned rather than markup-owned (it changes
    // while a scan runs), so it needs the same first pass every other string
    // gets from applyI18n.
    setScanning(false);

    if (!Backend.isLive()) {
      // Say so, once, in the place a reviewer will look: the warnings list.
      var noted = false;
      Backend.invoke("app_info").then(function (info) {
        appInfo = info;
        render();
      });
      void noted;
    } else {
      Backend.invoke("app_info").then(function (info) {
        appInfo = info;
        render();
      }).catch(function () { render(); });
    }

    Backend.listen("scan://progress", function (p) {
      if (!p) return;
      state.progress.push({
        collector: p.collector,
        elapsedMs: p.elapsedMs,
        findingsAdded: p.findingsAdded,
        error: p.error == null ? null : String(p.error)
      });
      renderProgress();
    });

    // Render the pre-scan state immediately: every pane is deliberate before any
    // data exists, and nothing moves when it arrives.
    render();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
}());
