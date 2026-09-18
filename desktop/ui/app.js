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
    "band.verdict": "ВЕРДИКТ ПО ПРОВЕРКЕ",
    "sev.high": "ВЫСОКИЙ",
    "sev.med": "СРЕДНИЙ",
    "sev.info": "ИНФО",
    "rec.actions": "ЧТО ДЕЛАТЬ ДАЛЬШЕ",
    "band.notRun": "Проверка ещё не запускалась",

    /* Change strip. */
    "delta.heading": "С ПРОШЛОЙ ПРОВЕРКИ",
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
    "progress.finished": "завершена, отчитались коллекторов: {n}",
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
      "Записи автозапуска с именем «{value}» нет в {hive}\{key}. Возможно, она уже удалена.",

    /* Wizard. The three steps the window walks through: what this is, what it
       is doing, and what came out of it. The step number and name are printed
       as text next to the dots, so the dots are a second telling of a fact the
       screen already states in words. */
    "wz.step1": "ШАГ 1 ИЗ 3 · ЧТО ЭТО",
    "wz.step2": "ШАГ 2 ИЗ 3 · ПРОВЕРКА",
    "wz.step3": "ШАГ 3 ИЗ 3 · ОТЧЁТ",
    "wz.back": "Назад",
    "wz.skip": "Перейти к отчету",

    "wz.welcome.title": "Проверка на скрытое наблюдение",
    "wz.welcome.l1":
      "Программа читает журналы, службы, задачи и сетевые соединения этой машины " +
      "и показывает то, что ищет за вами.",
    "wz.welcome.l2":
      "Она ничего не изменяет: только читает. Ни одно действие на этом шаге " +
      "не трогает диск, реестр и сеть.",
    "wz.welcome.l3": "Проверка занимает несколько секунд. Отчёт можно сохранить в файл.",
    "wz.welcome.start": "Начать проверку",
    "wz.welcome.readonly": "Только чтение",
    "wz.welcome.report": "Открыть отчёт",

    "wz.scan.title": "Идёт проверка",
    "wz.scan.wait":
      "Можно не ждать: проверка идёт в фоне, окно остаётся отзывчивым. " +
      "Находки уже собираются и появятся разбором на следующем шаге.",
    "wz.scan.collector": "Сейчас работает",
    "wz.scan.reported": "Отчитались коллекторов: {n} из {total}",
    "wz.scan.reportedUnknown": "Отчитались коллекторов: {n}",
    "wz.scan.elapsed": "Прошло: {time}",
    "wz.scan.findings": "Находок: {n}",
    "wz.scan.starting": "запуск…",

    "wz.result.title": "Проверка завершена",
    "wz.result.high": "ВЫСОКИЙ",
    "wz.result.med": "СРЕДНИЙ",
    "wz.result.info": "ИНФО",
    "wz.result.highNote": "Прямые признаки скрытого наблюдения или удалённого управления.",
    "wz.result.medNote": "Подозрительно само по себе, но нужен контекст машины.",
    "wz.result.infoNote": "Замечено, но решает не это: сведения для полноты картины.",
    "wz.result.headlineClean":
      "Признаков скрытого наблюдения не найдено. Это не доказывает, что машина " +
      "чиста: часть проверок могла не запуститься, а руткит уровня ядра не виден " +
      "ни одной из них.",
    "wz.result.headlineIncomplete":
      "Проверка завершилась не полностью: часть коллекторов не отработала. " +
      "Пустой список находок после такой проверки ничего не доказывает - " +
      "посмотрите предупреждения внизу окна или запустите проверку с правами администратора.",
    "wz.result.headlineWarn":
      "Найдено то, что требует внимания. Прочитайте находки на этом же экране " +
      "ниже, прежде чем что-либо удалять: это доказательства.",
    "wz.result.next": "ЧТО ДЕЛАТЬ ДАЛЬШЕ",
    "wz.result.next1": "Разберите находки ниже на этом же экране: у каждой есть доказательства.",
    "wz.result.next2":
      "Сохраните отчёт на внешний носитель до того, как что-либо менять на машине.",
    "wz.result.next3":
      "Ничего не удаляйте до сохранения отчёта: файл на диске и есть доказательство.",
    "wz.result.saveHint":
      "Файл сохраняется на эту машину - программа работает без сети и ничего никуда " +
      "не отправляет. Выберите путь в системном окне; готовый путь появится ниже.",
    "wz.result.saveLabel": "Путь",
    "wz.result.saved": "Отчёт сохранён: {path}",
    "wz.result.savedJson": "JSON сохранён: {path}",
    "wz.result.fromStep": "Вернуться к началу",
    "wz.result.done": "Свернуть сводку",
    "wz.result.view": "Показать отчёт",
    "wz.result.viewTitle": "Содержимое отчёта",
    "wz.result.viewClose": "Скрыть",
    "wz.result.viewLoading": "Читаю отчёт…",
    "wz.result.viewFail": "Не удалось показать отчёт: {message}"
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

    "band.verdict": "Verdict of the run",
    "sev.high": "HIGH",
    "sev.med": "MED",
    "sev.info": "INFO",
    "rec.actions": "Recommended actions",
    "band.notRun": "No scan has been run yet.",

    "delta.heading": "Since the last scan",
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
      "No autostart entry named \"{value}\" under {hive}\\{key}. It may already have been removed.",

    "wz.step1": "STEP 1 OF 3 \u00B7 WHAT THIS IS",
    "wz.step2": "STEP 2 OF 3 \u00B7 SCANNING",
    "wz.step3": "STEP 3 OF 3 \u00B7 REPORT",
    "wz.back": "Back",
    "wz.skip": "Skip to the report",

    "wz.welcome.title": "A check for hidden monitoring software",
    "wz.welcome.l1":
      "This reads the logs, services, tasks and network connections of this machine " +
      "and shows what is watching it.",
    "wz.welcome.l2":
      "It changes nothing: it only reads. Nothing on this step touches the disk, " +
      "the registry or the network.",
    "wz.welcome.l3": "The check takes a few seconds. Its report can be saved to a file.",
    "wz.welcome.start": "Start the check",
    "wz.welcome.readonly": "Read only",
    "wz.welcome.report": "Open the report",

    "wz.scan.title": "Scanning",
    "wz.scan.wait":
      "You do not have to wait: the scan runs in the background and the window stays " +
      "responsive. Findings are already being collected and are laid out on the next step.",
    "wz.scan.collector": "Running now",
    "wz.scan.reported": "{n} of {total} collectors have reported",
    "wz.scan.reportedUnknown": "{n} collectors have reported",
    "wz.scan.elapsed": "Elapsed: {time}",
    "wz.scan.findings": "Findings so far: {n}",
    "wz.scan.starting": "starting\u2026",

    "wz.result.title": "The check finished",
    "wz.result.high": "HIGH",
    "wz.result.med": "MED",
    "wz.result.info": "INFO",
    "wz.result.highNote": "Direct signs of hidden monitoring or remote control.",
    "wz.result.medNote": "Suspicious on its own, but it needs this machine's context.",
    "wz.result.infoNote": "Noticed, not decisive: context for the picture as a whole.",
    "wz.result.headlineClean":
      "No signs of hidden monitoring were found. That is not proof of a clean machine: " +
      "some checks may not have run, and a kernel-mode rootkit is invisible to all of them.",
    "wz.result.headlineIncomplete":
      "The scan did not finish: some collectors did not run. An empty finding list after " +
      "an incomplete scan proves nothing - read the warnings at the bottom of the window, " +
      "or run the check elevated.",
    "wz.result.headlineWarn":
      "Something was found that needs attention. Read the findings further down this same " +
      "screen before removing anything: they are the evidence.",
    "wz.result.next": "WHAT TO DO NEXT",
    "wz.result.next1": "Work through the findings below, on this same screen: each one carries its evidence.",
    "wz.result.next2": "Save the report to external media before changing anything on the machine.",
    "wz.result.next3": "Remove nothing before the report is saved: the file on disk is the evidence.",
    "wz.result.saveHint":
      "The file is written on this machine - the tool runs offline and sends nothing " +
      "anywhere. Pick a path in the system dialog; the path it used appears below.",
    "wz.result.saveLabel": "Path",
    "wz.result.saved": "Report saved: {path}",
    "wz.result.savedJson": "JSON saved: {path}",
    "wz.result.fromStep": "Back to the start",
    "wz.result.done": "Close the summary",
    "wz.result.view": "View report",
    "wz.result.viewTitle": "Report contents",
    "wz.result.viewClose": "Hide",
    "wz.result.viewLoading": "Reading the report…",
    "wz.result.viewFail": "The report could not be shown: {message}"
  };

  /* Which language to speak.
     The machine answers this question, and only the shell can read the answer: WebView2
     reports `navigator.language` as `en-US` on a Russian Windows, so a front end that
     decides for itself gets English on a Russian machine. `app_info` carries a
     `language` field read from `GetUserDefaultLocaleName` instead, and boot() installs
     that value here before the first paint. `navigator.language` is the fallback for a
     plain browser, where there is no shell to ask: a tag beginning "ru" gets Russian,
     anything else gets English. There is still no switch in the UI - one machine, one
     answer. */
  var LANG = "";

  /** Turn a locale tag into a dictionary name. Same rule either way it is used. */
  function languageOf(tag) {
    return /^ru\b/i.test(String(tag || "")) ? "ru" : "en";
  }

  /** The tag a browser can offer, for the fallback path. */
  function navigatorTag() {
    var n = null;
    try { n = typeof navigator !== "undefined" ? navigator : null; } catch (e) { n = null; }
    return n ? (n.languages && n.languages.length ? n.languages[0] : n.language) : "";
  }

  var DICT = EN;
  var FALLBACK = RU;

  /**
   * Install the language and point the dictionaries at it.
   *
   * Separate from boot() because the answer arrives asynchronously from the shell: the
   * page paints in the fallback first and re-renders once `app_info` lands, so a slow or
   * failing command shows a usable window instead of a blank one.
   *
   * @param {string} lang "ru" or "en"; anything else is treated as English.
   */
  function setLanguage(lang) {
    LANG = lang === "ru" ? "ru" : "en";
    DICT = LANG === "ru" ? RU : EN;
    FALLBACK = LANG === "ru" ? EN : RU;
  }

  setLanguage(languageOf(navigatorTag()));

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

  /* The demo answers with the tag the browser can see - the same fallback the real path
     uses when there is no shell to ask. `languageOf` is a hoisted function declaration,
     so it is callable here even though the language block sits further down the file. */
  var DEMO_APP_INFO = {
    version: "0.1.0",
    needles: 1911,
    yaraRules: 6,
    collectors: 14,
    language: languageOf(navigatorTag())
  };

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

  /**
   * A stand-in for the rendered report, for the browser harness only.
   *
   * Deliberately a few lines of the real layout - the box-drawing header, a
   * finding with its evidence, the closing note - because the point of looking
   * at it is to see whether the fixed-width columns survive the panel: the
   * wrapping, the horizontal scroll and the line height can only be judged
   * against text that has the real shape.
   */
  var DEMO_REPORT_EXCERPT = [
    "IRSCAN - read-only Windows endpoint triage",
    "host      LUXTVTZ",
    "time      2026-09-17 00:41:12",
    "tool      0.1.0",
    "",
    "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550",
    "HIGH 1   MED 4   INFO 83   - something was found that needs attention",
    "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550",
    "",
    "[HIGH] A service was installed and logged by the Service Control Manager",
    "       service:  RemoteAccessAgent",
    "       file:     C:\\ProgramData\\rma\\agent.exe",
    "       time:     2026-09-16 03:12:44",
    "       why:      the name matches a known remote-access tool",
    "",
    "  This is what the file on disk will contain, byte for byte."
  ].join("\n");

  function demoCall(cmd, args) {
    if (cmd === "app_info") return Promise.resolve(DEMO_APP_INFO);
    if (cmd === "export_report") {
      return Promise.resolve((args && args.path) || "C:\\Users\\x\\report.txt");
    }
    // The real shell returns the rendered report; the stand-in has none, so it
    // says so in the same shape a missing command would. A silent empty string
    // would make the report view look finished when nothing had been read.
    if (cmd === "report_text") {
      return Promise.resolve(DEMO_REPORT_EXCERPT);
    }
    if (cmd === "disable_service" || cmd === "remove_autostart") {
      return demoRemediate(cmd, args);
    }
    if (cmd === "scan") {
      // Resolved only once the stand-in has emitted, so the promise the UI
      // waits on settles in the same order the shell settles it: after the
      // last progress event. A browser run that finished before its own first
      // event would make the working step unreachable outside the shell.
      var emitted = demoRunProgress();
      var payload = {};
      var k;
      for (k in DEMO_PAYLOAD) {
        if (Object.prototype.hasOwnProperty.call(DEMO_PAYLOAD, k)) payload[k] = DEMO_PAYLOAD[k];
      }
      payload.delta = demoDeltaState();
      if (!emitted) return Promise.resolve(payload);
      // A failed emit must not strand the run: the report is what matters, and
      // the stand-in is for looking at the interface.
      return emitted.then(function () { return payload; }, function () { return payload; });
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
    if (!handler) return null;
    var added = [0, 1, 4, 3, 6, 0, 2, 1, 5, 12, 1, 9, 205, 0];
    var step = function (i) {
      if (i >= DEMO_COLLECTORS.length) return Promise.resolve();
      return new Promise(function (done) {
        window.setTimeout(function () {
          handler({
            collector: DEMO_COLLECTORS[i],
            elapsedMs: 120 + i * 730,
            findingsAdded: added[i],
            error: DEMO_COLLECTORS[i] === "events"
              ? "журнал безопасности недоступен: EvtQuery завершился с ошибкой Win32 5 (отказано в доступе)"
              : null
          });
          done();
        }, 90);
      }).then(function () { return step(i + 1); });
    };
    return step(0);
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

    // Wizard. Last, because it needs nothing the report's own lookup provides,
    // and because a missing wrapper must not stop the report from being cached.
    cacheWizardDom();
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

    // The three big numbers are the backend's verdict. Before a scan there is
    // nothing to count, and an em dash is honest about that. They are also the
    // only place a severity count appears: the filter buttons below the band
    // carry labels, not the same three numbers a second time.
    ["high", "med", "info"].forEach(function (s) {
      var n = has ? v[s] : null;
      dom.counts[s].textContent = typeof n === "number" ? String(n) : "\u2014";
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
    // The progress list and the "since last time" strip share one reserved box.
    // While a run is in flight the collector rows are what that box is for; the
    // strip returns when the run ends. Showing both at once would print half a
    // comparison under half a collector list.
    dom.delta.hidden = active;
    if (!active) {
      clear(dom.progressList);
      renderWizardProgress();
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

    // The wizard's scan step counts the same list: one source for the count,
    // so the two cannot disagree about how many collectors have reported.
    renderWizardProgress();
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
    // The wizard's two buttons export the same report and are busy with it too.
    Wiz.saving = on;
    renderWizard();
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
      return wizardPicking()
        ? wzPickPath(opts.defaultPath, format)
        : askPathFallback(opts.defaultPath, format);
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
        // Same answer, in the place the button that asked for it lives. A run
        // of attempts belongs next to its buttons, not in a header that has
        // already emptied itself back to the host name.
        wizardShowSaved(t(format === "json"
          ? "wz.result.savedJson" : "wz.result.saved", { path: where }), false);
      }, function (err) {
        var why = t("save.fail", { message: describeError(err) });
        showSaveConfirmation(why, true);
        setSaving(false);
        wizardShowSaved(why, true);
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
    renderWizard();
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

    // The header's Scan button is still there and still means this. If the
    // wizard is up, the run gets its own step over the report.
    wizardOnScanStart();
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
      // A scan that failed is still a finished scan: the wizard leaves its
      // working step either way, and the report says what happened.
      wizardScanFinished();
      render();
      // Only an automatic run carries the user forward. A scan someone asked
      // for from the header after closing the overlay leaves them where they are
      // - opening a screen nobody asked for is its own kind of rude.
      if (dom.wizard && Wiz.open && Wiz.autoStarted) {
        Wiz.autoStarted = false;
        wizardOpen(2);
      }
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

  /* ============================================================ 6b. wizard ==
   * The window's top-level flow: what this is, what it is doing, what came out
   * of it. Three steps, one at a time, over the report that already exists
   * underneath them.
   *
   * The wizard is a LENS, not a second renderer. It reads the same `state` the
   * panes read, and the report screen is a summary plus a viewport onto the real
   * findings list and detail pane - those keep their ids, their renderers and
   * their keyboard behaviour, and nothing here restructures them.
   *
   * None of the three steps is a dead end and none of them is a gate: the header
   * stays reachable, and the report is always one step away from the scan step.
   * A progress screen nobody can leave is a worse screen than no wizard at all.
   */

  /* The panels, in step order. An array rather than a bitmask because it is
     read in a loop that has to keep working when a panel is missing. */
  var WZ_PANELS = ["wstep-welcome", "wstep-scan", "wstep-result"];
  var WZ_MARK = ["wzWelcome", "wzScan", "wzResult"];

  /**
   * The wizard's own state, and the only thing the step machine consults.
   *
   * `shown`/`open` describe markup mode: with no wrapper both start true, so a
   * host serving these files without one gets the report and nothing else.
   *
   * `autoStarted` makes the start button idempotent: a double click or a held
   * Enter cannot begin two scans, because `runScan` refuses to run twice and the
   * step would then be left waiting on the first one.
   */
  var Wiz = {
    step: 0,
    open: true,
    launching: false,
    result: null,
    // The rendered report, fetched on demand and kept for the scan it belongs to.
    // A new run must clear it, or the panel would show the previous scan's report
    // beside the current scan's numbers - the one comparison that must never lie.
    report: null,
    saving: false,
    autoStarted: false,
    reached: [false, false, false],
    timer: 0,
    autoTimer: 0,
    startedAt: 0,
    doneAt: 0
  };

  /** How long the welcome step is shown before the run starts by itself.
   *  Long enough to read three lines and stop it; short enough that nobody
   *  sits in front of a screen waiting for something to happen. */
  var WIZ_AUTO_START_MS = 2600;

  /** What the background indicator is doing. Motion, never the only signal:
   *  the same fact is a word in `wz.scan.collector`. */
  var WZ_FRAME = ["\u25CB", "\u25D4", "\u25D1", "\u25D0"];

  /** The dot indicator, as a node map so its text nodes are replaced in place
   *  rather than rebuilt: a fresh element every 120ms would be a garbage churn
   *  in the middle of a scan. */
  function makePhrase() {
    var dots = [];
    // One dot per step, taken from the panel list rather than written as a
    // number: a fourth dot for a three-step flow renders as an ornament with
    // no meaning, and reads on screen as an inconsistent grey blob.
    for (var i = 0; i < WZ_PANELS.length; i++) dots.push(el("span", "wz-dot"));
    var box = el("span", "wz-phrase");
    box.setAttribute("aria-hidden", "true");
    dots.forEach(function (d) { box.appendChild(d); });
    box.dots = dots;
    return box;
  }

  function stepPhrase(node, step) {
    // One dot per step, filled up to the current one. The same fact is written
    // out in the label beside it, so the dots are never the only telling.
    var dots = node && node.dots ? node.dots : [];
    for (var i = 0; i < dots.length; i++) {
      var on = i <= step;
      dots[i].textContent = on ? "\u25CF" : "\u25CB";
      dots[i].className = "wz-dot" + (on ? " is-on" : "");
    }
  }

  /** Seconds in one place, because a running clock is a string that changes four
   *  times a second and nobody needs a tenth of a second. */
  function elapsedText(ms) {
    var total = Math.max(0, Math.floor(ms / 1000));
    var m = Math.floor(total / 60);
    var s = total % 60;
    return m + ":" + (s < 10 ? "0" : "") + s;
  }

  /** True when this screen is the one a save was asked from: its own path
   *  control is inside the step, where the button that asked for it is. */
  function wizardPicking() {
    return !!(Wiz.open && Wiz.step === 2 && dom.wzPick);
  }

  /** Total collectors, from the app info the shell already reports. Zero when
   *  unknown, and the caller then says "N reported" rather than inventing a
   *  denominator it does not have. */
  function collectorTotal() {
    var n = appInfo && appInfo.collectors;
    return typeof n === "number" && n > 0 ? n : 0;
  }

  /**
   * Enter a step. Idempotent, and the only writer of `Wiz.step`.
   *
   * The whole visible change is one class, so a step change is one layout pass
   * for the overlay instead of one per panel. `wizard-cover` is what hides the
   * report: `visibility` rather than `display`, because display:none collapses
   * every box underneath it (the panes' reserved heights are measured from the
   * bottom of the window) and the report would then be re-laid-out the moment
   * it reappears.
   */
  function wzEnter(step, opts) {
    var o = opts || {};
    var s = Math.max(0, Math.min(WZ_PANELS.length - 1, step | 0));
    Wiz.step = s;
    Wiz.reached[s] = true;

    var wrap = dom.wizard;
    if (!wrap) return;
    wrap.classList.toggle("wizard-cover", s !== 2);
    var i;
    for (i = 0; i < WZ_PANELS.length; i++) {
      var panel = dom[WZ_MARK[i]];
      if (!panel) continue;
      var on = i === s;
      panel.classList.toggle("is-on", on);
      // Focus moves with the step, or a keyboard user is left tabbing through a
      // panel they cannot see.
      if (on) panel.removeAttribute("aria-hidden");
      else panel.setAttribute("aria-hidden", "true");
    }
    stepPhrase(dom.wzDots, s);
    // The rail's three labels carry the same fact as the dots, in words. Both
    // are written here so the two tellings cannot disagree: a rail whose dots
    // say step 2 while its brightest label still says step 1 is worse than no
    // rail at all, because it is a screen contradicting itself.
    for (i = 0; i < WZ_PANELS.length; i++) {
      var lbl = dom.wzStepLabels && dom.wzStepLabels["wz.step" + (i + 1)];
      if (lbl) lbl.classList.toggle("is-on", i === s);
    }
    renderWizard();

    if (s === 0) wizardStopClock();
    if (s === 1) {
      if (dom.wzSkip) dom.wzSkip.focus();
    }
    if (s === 2 && o.focus !== false) {
      wizardStopClock();
      if (dom.wzBack) dom.wzBack.focus();
    }
  }

  /** Leave the wizard for the report. The header and the list stay live; this
   *  is a view change, not a navigation. */
  function wizardClose() {
    if (!Wiz.open) return;
    Wiz.open = false;
    if (dom.wizard) {
      dom.wizard.classList.remove("is-open");
      // `wizard-cover` is what dims the report, and it is a separate class from
      // `is-open` because the report step keeps it OFF while the overlay is
      // still open. Leaving it on here dimmed the whole window to 14% the moment
      // the overlay closed, which made the report unreadable - the exact
      // opposite of what this function is for.
      dom.wizard.classList.remove("wizard-cover");
    }
    // A pending automatic run must not fire into a closed wizard.
    if (Wiz.autoTimer) { window.clearTimeout(Wiz.autoTimer); Wiz.autoTimer = 0; }
    wizardStopClock();
    if (dom.search && dom.search.focus) dom.search.focus();
  }

  /** Bring the overlay back, on whatever step the state justifies. */
  function wizardOpen(step) {
    if (!dom.wizard) return;
    Wiz.open = true;
    dom.wizard.classList.add("is-open");
    wzEnter(step === undefined ? Wiz.step : step);
  }

  /**
   * The live clock and the animated indicator. One interval, started only while
   * the scan step is on screen and the scan is running, and stopped on every
   * exit path - a timer left behind would keep a finished screen repainting.
   */
  function wizardTick() {
    var ms = (Wiz.doneAt || Date.now()) - Wiz.startedAt;
    if (dom.wzElapsed) {
      dom.wzElapsed.textContent = t("wz.scan.elapsed", { time: elapsedText(ms) });
    }
    var n = state.progress.length;
    if (state.scanning && dom.wzCollector) {
      // The collector identifier is the core's name for the collector: it stays
      // Latin, exactly as it is in the progress list and in a log someone greps.
      var last = n > 0 ? state.progress[n - 1].collector : null;
      var word = last == null ? t("wz.scan.starting") : String(last);
      clear(dom.wzCollector);
      dom.wzCollector.appendChild(el("span", "wz-label", t("wz.scan.collector")));
      var name = el("span", "wz-name", word);
      if (last != null) name.title = t("collector." + String(last));
      dom.wzCollector.appendChild(name);
      // Announce the identifier, not the whole line: the count and the clock
      // change constantly and a screen reader should not read them out again.
      if (last != null && dom.wzLive && dom.wzLive.textContent !== String(last)) {
        dom.wzLive.textContent = String(last);
      }
    }
    if (dom.wzFrame) dom.wzFrame.textContent = WZ_FRAME[Math.floor(ms / 120) % WZ_FRAME.length];
  }

  function wizardStartClock() {
    if (Wiz.timer) return;
    if (!Wiz.startedAt) Wiz.startedAt = Date.now();
    Wiz.timer = window.setInterval(wizardTick, 120);
  }

  function wizardStopClock() {
    if (!Wiz.timer) return;
    window.clearInterval(Wiz.timer);
    Wiz.timer = 0;
  }

  /**
   * Enter the scanning step and start the scan behind it.
   *
   * A hop, not a start: the step is on screen before the command is sent, so a
   * slow scan is visible rather than a button that appears to have done nothing.
   */
  function wizardStart(byUser) {
    if (Wiz.launching) return;
    // A start cancels a pending automatic one. Without this, pressing the button
    // leaves the timer armed and a second scan begins on an already-finished run.
    if (Wiz.autoTimer) { window.clearTimeout(Wiz.autoTimer); Wiz.autoTimer = 0; }
    Wiz.launching = true;
    Wiz.autoStarted = byUser !== false;
    Wiz.startedAt = Date.now();
    Wiz.doneAt = 0;
    // A new run invalidates the report held for the old one, and hides the panel
    // if it was open, so nothing from the previous scan can be read as this one's.
    Wiz.report = null;
    if (dom.wzViewPanel) dom.wzViewPanel.hidden = true;
    wzEnter(1);
    wizardStartClock();
    wizardTick();
    runScan();
  }

  /** Called by runScan, from both of its endings. */
  function wizardScanFinished() {
    Wiz.launching = false;
    Wiz.doneAt = Date.now();
    wizardStopClock();
    wizardTick();
  }

  /** The report screen's summary: counts, what they mean, and what to do next.
   *  The counts are the backend's numbers; only the words around them are this
   *  file's. */
  function wizardRenderResult() {
    var sum = dom.wzSummary;
    if (!sum) return;
    clear(sum);

    var v = (state.payload && state.payload.verdict) || null;
    var warnings = state.payload ? asArray(state.payload.warnings) : [];
    var failed = 0;
    state.progress.forEach(function (p) { if (p.error) failed++; });
    var haveHigh = !!(v && v.high > 0);
    var haveAny = !!(v && (v.high > 0 || v.med > 0 || v.info > 0));
    var incomplete = !state.payload || failed > 0 || warnings.length > 0;

    var headKey = haveAny ? "wz.result.headlineWarn"
      : (incomplete ? "wz.result.headlineIncomplete" : "wz.result.headlineClean");
    var head = el("p", haveHigh ? "wz-headline is-high" : "wz-headline", t(headKey));
    sum.appendChild(head);

    var nums = el("div", "wz-nums");
    [["high", "wz.result.high", "wz.result.highNote"],
     ["med", "wz.result.med", "wz.result.medNote"],
     ["info", "wz.result.info", "wz.result.infoNote"]].forEach(function (row) {
      var box = el("div", "wz-num");
      box.setAttribute("data-sev", row[0]);
      box.appendChild(el("span", "wz-num-glyph glyph", glyph(row[0])));
      box.appendChild(el("span", "wz-num-count",
        v && typeof v[row[0]] === "number" ? String(v[row[0]]) : "\u2014"));
      box.appendChild(el("span", "wz-num-label", t(row[1])));
      box.appendChild(el("span", "wz-num-note", t(row[2])));
      nums.appendChild(box);
    });
    sum.appendChild(nums);

    var next = el("div", "wz-next");
    next.appendChild(el("h3", "wz-next-head", t("wz.result.next")));
    var ol = el("ol", "wz-next-list");
    // A failed run has no findings to read, so the first instruction becomes the
    // one that matters then: the check did not complete, run it again.
    var keys = haveAny ? ["wz.result.next1", "wz.result.next2", "wz.result.next3"]
      : (incomplete ? ["wz.result.headlineIncomplete", "wz.result.next2"]
        : ["wz.result.next1", "wz.result.next2", "wz.result.next3"]);
    keys.forEach(function (k) {
      ol.appendChild(el("li", k === keys[0] ? null : "is-quiet", t(k)));
    });
    next.appendChild(ol);
    sum.appendChild(next);
  }

  /** The report screen. Cheap enough to call on every render. */
  function renderWizard() {
    if (!dom.wizard) return;
    wizardRenderResult();
    if (dom.wzSaveTxt) dom.wzSaveTxt.disabled = Wiz.saving || !state.payload;
    if (dom.wzSaveJson) dom.wzSaveJson.disabled = Wiz.saving || !state.payload;
    // Reading the report is not gated on saving, so it follows `hasScan`, not
    // `Wiz.saving`: a person may well read it and decide not to save at all.
    if (dom.wzViewBtn) dom.wzViewBtn.disabled = !state.payload;
    // The skip button exists to leave a scan that is still running. Once the
    // scan has ended it has nothing left to do, so it goes away rather than
    // sitting there disabled: a greyed-out button with no enabled alternative
    // reads as a screen that is stuck, and this one is not.
    if (dom.wzSkip) dom.wzSkip.hidden = !state.scanning;
    var box = dom.wzSavedWrap;
    if (box) {
      box.hidden = !Wiz.result;
      if (Wiz.result) {
        box.setAttribute("data-op", Wiz.result.bad ? "err" : "ok");
        dom.wzSaved.textContent = Wiz.result.text;
      }
    }
  }

  /** The scanning step's counts. Called from renderProgress, so the wizard and
   *  the strip below it can never disagree about how many have reported. */
  function renderWizardProgress() {
    if (!dom.wizard || !Wiz.open || Wiz.step !== 1) return;
    var n = state.progress.length;
    var total = collectorTotal();
    var said = total
      ? t("wz.scan.reported", { n: n, total: total })
      : t("wz.scan.reportedUnknown", { n: n });
    if (dom.wzReported) dom.wzReported.textContent = said;
    // The count is also the accessible reading: there is no meter element to
    // carry it, because the meter could not be made to fill (see .wz-barline).
    if (dom.wzReported) dom.wzReported.setAttribute("aria-live", "polite");
    if (dom.wzCollected) {
      var findings = state.payload && state.payload.groups ? asArray(state.payload.groups).length : 0;
      dom.wzCollected.textContent = t("wz.scan.findings", { n: findings });
    }
  }

  /* ---------------------------------------------- the wizard's own saving -- */
  /**
   * `saveReport` is the report's only writer and keeps its behaviour, including
   * the browser's path box - except for one thing: when this screen's buttons
   * are the ones that asked, the choosing happens here, inside the step, instead
   * of in a header that is covered while steps one and two are on screen.
   *
   * The outcome is also reported through the existing `showSaveConfirmation`,
   * which is what the header buttons' answer is.
   */
  var wzPickHost = null;

  function wzPickOk(path) {
    if (!wzPickHost) return;
    wzPickHost.hidden = true;
    wzPickHost.input.value = path;
  }

  function wzPickCancel() {
    if (!wzPickHost) return;
    wzPickHost.hidden = true;
  }

  function wzPickPath(defaultPath, format) {
    var host = dom.wzPick;
    if (!host) return Promise.resolve(defaultPath);
    if (!wzPickHost) {
      // Selects, not a text field: this host has no dialog plugin, so the
      // extension is the only part of the name the user is choosing.
      wzPickHost = el("div", "wz-pick-nav");
      var lab = el("label", "action-field wide save-path");
      lab.appendChild(el("span", null, t("save.as")));
      var input = el("input");
      input.type = "text";
      input.autocomplete = "off";
      input.spellcheck = false;
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { e.preventDefault(); wzPickOk(input.value.trim() || defaultPath); }
        if (e.key === "Escape") { e.preventDefault(); wzPickCancel(); }
      });
      lab.appendChild(input);
      wzPickHost.appendChild(lab);
      wzPickHost.input = input;
      var row = el("div", "wz-pick-row");
      ["txt", "json"].forEach(function (f) {
        var b = el("button", "btn-ghost", f === "json" ? "JSON" : "TXT");
        b.type = "button";
        b.addEventListener("click", function () {
          wzPickOk(wzPickHost.input.value.trim() || defaultPath);
          saveReport(f);
        });
        row.appendChild(b);
      });
      var cancel = el("button", "btn-ghost", t("wz.back"));
      cancel.type = "button";
      cancel.addEventListener("click", wzPickCancel);
      row.appendChild(cancel);
      wzPickHost.appendChild(row);
      host.appendChild(wzPickHost);
    }
    wzPickHost.hidden = false;
    wzPickHost.input.value = defaultPath;
    window.setTimeout(function () { wzPickHost.input.focus(); wzPickHost.input.select(); }, 0);
    return Promise.resolve(defaultPath);
  }

  /** Record where the file went, next to the buttons that asked for it.
   *  `Wiz.result` starts null so a fresh attempt clears the previous answer
   *  rather than leaving a path from a run that no longer applies. */
  function wizardShowSaved(text, bad) {
    Wiz.saving = false;
    Wiz.result = { bad: !!bad, text: text };
    renderWizard();
  }

  function wizardSave(format) {
    if (Wiz.saving || !state.payload) return;
    Wiz.saving = true;
    Wiz.result = null;
    renderWizard();
    saveReport(format);
  }

  /**
   * Show or hide the rendered report inside the step.
   *
   * The text is fetched the first time and then kept in `Wiz.report`, because it
   * cannot change for a given scan - a second request would return the same
   * bytes and a second render would cost the same work for no new information.
   * `cursor` still goes with the request: the window must never show the report
   * of a scan it is no longer displaying, and that check lives in Rust.
   *
   * A failure is shown where the report would have been rather than only in a
   * toast: the person asked for the report, so the answer belongs under the
   * control they used.
   */
  function wizardToggleView() {
    if (!dom.wzViewPanel) return;
    var open = dom.wzViewPanel.hidden;

    if (!open) {
      dom.wzViewPanel.hidden = true;
      if (dom.wzViewBtn) dom.wzViewBtn.setAttribute("aria-expanded", "false");
      return;
    }

    dom.wzViewPanel.hidden = false;
    if (dom.wzViewBtn) dom.wzViewBtn.setAttribute("aria-expanded", "true");

    // Bring the panel into view. It opens below the buttons, which on this layout
    // lands past the bottom of the visible area, so without this the only feedback
    // is the button's own state and the reader concludes nothing happened. The CSS
    // file turns motion off under `prefers-reduced-motion`, and this scroll is
    // instant rather than smooth, so nothing here needs to ask about the setting.
    // The scrolling element is the step panel, not the window - the layout gives
    // `.wz-panel` its own `overflow: auto`, and `.wz-inner` centres with `margin:
    // auto 0`, so scrolling the document does nothing. The scroll has to happen
    // after the browser has laid the newly unhidden panel out, otherwise the
    // container still reports its old height and the scroll lands at zero.
    var scroller = dom.wzViewPanel.closest(".wz-panel") || dom.wzViewPanel.parentElement;
    if (scroller) {
      var toBottom = function () { scroller.scrollTop = scroller.scrollHeight; };
      window.requestAnimationFrame(toBottom);
    }

    if (Wiz.report != null) {
      dom.wzView.textContent = Wiz.report;
      return;
    }

    dom.wzView.textContent = t("wz.result.viewLoading");
    Backend.invoke("report_text", {
      json: false,
      cursor: state.payload ? state.payload.cursor : null
    }).then(function (body) {
      Wiz.report = body == null ? "" : String(body);
      dom.wzView.textContent = Wiz.report;
    }, function (err) {
      dom.wzView.textContent = t("wz.result.viewFail", { message: describeError(err) });
    });
  }

  function cacheWizardDom() {
    dom.wizard = $("wizard");
    dom.wzWelcome = $("wstep-welcome");
    dom.wzScan = $("wstep-scan");
    dom.wzResult = $("wstep-result");
    dom.wzSteps = $("step-dots");
    dom.wzDots = makePhrase();
    if (dom.wzSteps) dom.wzSteps.appendChild(dom.wzDots);
    dom.wzStart = $("wz-start");
    dom.wzReport = $("wz-report");
    dom.wzSkip = $("wz-skip");
    dom.wzFrame = $("wz-frame");
    dom.wzCollector = $("wz-collector");
    dom.wzLive = $("wz-live");
    dom.wzReported = $("wz-reported");
    dom.wzElapsed = $("wz-elapsed");
    dom.wzCollected = $("wz-collected");
    dom.wzSummary = $("wz-summary");
    dom.wzSaveTxt = $("wz-save-txt");
    dom.wzSaveJson = $("wz-save-json");
    dom.wzView = $("wz-view");
    dom.wzViewPanel = $("wz-view-panel");
    dom.wzViewBtn = $("wz-view-btn");
    dom.wzSaved = $("wz-saved");
    dom.wzSavedWrap = $("wz-saved-wrap");
    dom.wzPick = $("wz-pick");
    dom.wzBack = $("wz-back");
    dom.wzDone = $("wz-done");
    dom.wzStepLabels = {
      "wz.step1": $("wz-step1"),
      "wz.step2": $("wz-step2"),
      "wz.step3": $("wz-step3")
    };
  }

  function wireWizard() {
    if (!dom.wizard) return;
    // One listener for the overlay: every control in it is static in the markup,
    // so a handler per button would be five listeners saying the same thing.
    dom.wizard.addEventListener("click", function (e) {
      var id = e.target && e.target.id;
      if (id === "wz-start") { e.preventDefault(); wizardStart(true); return; }
      if (id === "wz-skip") { e.preventDefault(); wizardClose(); return; }
      if (id === "wz-report") { e.preventDefault(); wizardOpen(2); return; }
      if (id === "wz-save-txt") { e.preventDefault(); wizardSave("txt"); return; }
      if (id === "wz-save-json") { e.preventDefault(); wizardSave("json"); return; }
      if (id === "wz-view-btn" || id === "wz-view-close") {
        e.preventDefault();
        wizardToggleView();
        return;
      }
      if (id === "wz-back") { e.preventDefault(); wizardOpen(0); return; }
      if (id === "wz-done") { e.preventDefault(); wizardClose(); }
    });
  }

  /**
   * Boot for the wizard.
   *
   * `?wizard=0` starts with the overlay closed and no automatic scan: that is
   * how someone who wants the report - not the tour - reaches it, and it is the
   * only supported way to skip. The auto-start is the one scan this file
   * launches unasked, and it is what the welcome screen literally offers.
   */
  function wizardInit() {
    var q = "";
    try { q = String(window.location.search || ""); } catch (e) { q = ""; }
    var off = /[?&]wizard=0/.test(q);

    if (!dom.wizard) {
      // No wrapper in the markup (an older index.html, or a host serving these
      // files without it). Say nothing and change nothing: the report is the
      // product, and it must not depend on the tour.
      Wiz.open = false;
      return;
    }

    wzEnter(0, { focus: false });
    if (off) { wizardClose(); return; }
    wizardOpen(0);
    // The welcome step is shown for a moment before the run starts, and this
    // delay is load-bearing, not decoration. Starting the scan in the same task
    // that shows step one meant the step change beat the first paint: the window
    // opened straight onto "scanning", and the one screen that says what this
    // tool is - and that it changes nothing - was never displayed. In a tool
    // whose whole claim is "read-only, it changes nothing", that is the consent
    // statement going missing.
    //
    // A person can cut it short two ways: press Start (which runs immediately),
    // or press Enter on the already-focused button. After this window the run is
    // automatic, because the button the step offers means exactly this.
    Wiz.autoTimer = window.setTimeout(function () {
      Wiz.autoTimer = 0;
      wizardStart(false);
    }, WIZ_AUTO_START_MS);
  }

  /** The header's own Scan button, and anything else that starts a run: the
   *  scan step is what the window shows while one is in flight. */
  function wizardOnScanStart() {
    if (!dom.wizard || !Wiz.open) return;
    Wiz.launching = true;
    Wiz.autoStarted = true;
    Wiz.startedAt = Date.now();
    Wiz.doneAt = 0;
    wzEnter(1);
    wizardStartClock();
  }

  /* =============================================================== 7. boot == */

  function boot() {
    // The markup is filled from the dictionary before anything is cached or
    // rendered: the language decision has one home, and it happens once.
    applyI18n(document);
    cacheDom();
    wire();
    wireWizard();
    // The button label is renderer-owned rather than markup-owned (it changes
    // while a scan runs), so it needs the same first pass every other string
    // gets from applyI18n.
    setScanning(false);

    // The language comes back with app_info, and it is the whole reason this call
    // happens before the first real paint: applyI18n() ran above in the fallback
    // language, so if the shell disagrees the markup has to be filled again. Both
    // branches below do that through adopt().
    function adopt(info) {
      appInfo = info;
      var lang = info && info.language;
      // Only re-run the markup pass when the answer actually differs; a browser whose
      // fallback already matched must not be re-rendered for nothing.
      if (lang === "ru" || lang === "en") {
        if (lang !== LANG) {
          setLanguage(lang);
          applyI18n(document);
          setScanning(state.scanning);
          renderWizard();
        }
      }
      render();
    }

    Backend.invoke("app_info").then(adopt, function () {
      // No shell answer: keep the navigator fallback already installed and show the
      // window as it stands rather than leaving it empty.
      render();
    });

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

    // Last, because it starts a scan: the report has to exist underneath the
    // step that will uncover it, and `wizardInit` is what puts the window on
    // its first step. It is also the only thing here that lands with the
    // language already resolved, so the first screen a person reads is never a
    // frame of the wrong one.
    wizardInit();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
}());
