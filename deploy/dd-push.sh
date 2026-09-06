#!/bin/sh
# Заливка отчётов Trivy в DefectDojo.
#
#   sh deploy/dd-push.sh                     # все образы, тег latest
#   IMAGE_TAG=v0.4.2 sh deploy/dd-push.sh    # конкретная сборка
#   sh deploy/dd-push.sh gateway worker      # только эти цели
#   sh deploy/dd-push.sh repo                # только зависимости исходников
#   sh deploy/dd-push.sh sast                # только bandit и semgrep
#   DD_SBOM=0 sh deploy/dd-push.sh           # без SBOM, только уязвимости
#
# Без аргументов идут ВСЕ цели: шесть образов, зависимости репозитория и SAST.
# Полный прогон долгий, но выборочный по умолчанию означал бы, что проверка,
# которую забыли перечислить, тихо не выполняется годами.
#
# Доступ берётся из ~/.dd.env (chmod 600), чтобы токен не оседал в history:
#   DD_URL=https://defectdojo.abdullin.lab
#   DD_TOKEN=...
#
# SAST (bandit, semgrep) запускается через uvx, если инструмента нет на PATH:
# в pyproject он не нужен, ставить его в окружение проекта незачем, а pip в
# этом репозитории запрещён.
#
# На каждую цель-образ уходит две заливки: отчёт trivy (уязвимости, секреты,
# мисконфиги) и CycloneDX SBOM. Они живут в разных engagement и под разными
# scan_type, поэтому close_old_findings одного не трогает находки другого.
#
# Скрипт зовёт reimport-scan, а не import-scan. Разница видна не сразу:
# import создаёт новый Test на каждый запуск, и через месяц в engagement
# тридцать тестов с одними и теми же CVE, а «когда уязвимость появилась»
# и «когда закрылась» посчитать уже нельзя. reimport дописывает в тот же
# Test: исчезнувшее закрывает, вернувшееся переоткрывает.
set -u

# ---------------------------------------------------------------- настройки

# Файл читается, только если токен не пришёл из окружения. Иначе на раннере
# CI победил бы случайно оставшийся ~/.dd.env, и заливка молча ушла бы не в
# тот DefectDojo — а выглядело бы это как успешный прогон.
if [ -z "${DD_TOKEN:-}" ] && [ -f "$HOME/.dd.env" ]; then
	set -a
	. "$HOME/.dd.env"
	set +a
fi

DD_URL=${DD_URL:-}
DD_TOKEN=${DD_TOKEN:-}
IMAGE_TAG=${IMAGE_TAG:-latest}
IMAGE_NAMESPACE=${IMAGE_NAMESPACE:-dato1}
DD_PRODUCT_TYPE=${DD_PRODUCT_TYPE:-vulnscantg}
DD_ENGAGEMENT=${DD_ENGAGEMENT:-container-scan}
# Info у trivy — это в основном unfixed-пакеты базового образа. С ними
# продукт нечитаем, и настоящие находки тонут.
DD_MIN_SEVERITY=${DD_MIN_SEVERITY:-Low}
# Лаборатория под самоподписанным сертификатом. -k снимает проверку целиком:
# токен уходит в соединение, подлинность которого никто не подтверждает.
# Внутри лаборатории это осознанный размен, снаружи — нет. DD_INSECURE=0 его
# отменяет, не трогая остальной скрипт.
DD_INSECURE=${DD_INSECURE:-1}
# Если задан — JSON-отчёты и SBOM остаются здесь, иначе удаляются вместе с tmp.
DD_REPORT_DIR=${DD_REPORT_DIR:-}

# SBOM. Формат: cyclonedx | spdx-json.
DD_SBOM=${DD_SBOM:-1}
DD_SBOM_ENGAGEMENT=${DD_SBOM_ENGAGEMENT:-sbom}
DD_SBOM_FORMAT=${DD_SBOM_FORMAT:-cyclonedx}
# У trivy "--format cyclonedx" ВЫКЛЮЧАЕТ поиск уязвимостей, и без этого флага
# в BOM нет секции vulnerabilities. А парсер DefectDojo строит находки только
# из неё: компоненты сами по себе попадают в инвентарь лишь при включённом
# V3_FEATURE_LOCATIONS, которого в OSS-установке по умолчанию нет. Итог —
# чистый SBOM залился бы «успешно» и не дал ровно ничего видимого.
DD_SBOM_WITH_VULNS=${DD_SBOM_WITH_VULNS:-1}

# SAST. Реестровые конфиги p/* semgrep тянет с semgrep.dev по сети; если это
# неприемлемо, укажите здесь путь к локальному каталогу с правилами.
DD_SAST_ENGAGEMENT=${DD_SAST_ENGAGEMENT:-sast}
DD_SEMGREP_CONFIG=${DD_SEMGREP_CONFIG:-"p/python p/security-audit p/secrets \
p/trailofbits p/command-injection p/sql-injection p/insecure-transport p/fastapi"}
# p/bandit намеренно не включён: bandit идёт отдельным шагом, и те же находки
# пришли бы в DefectDojo дважды, из разных парсеров, где дедупликация их не
# свяжет. p/owasp-top-ten тоже: 560 правил на все языки, для Python почти всё
# уже есть выше, зато semgrep спотыкается на shell-скриптах и пишет ошибки
# разбора прямо в отчёт.
#
# Документация исключена: правила вроде curl-unencrypted-url срабатывают на
# примерах команд в markdown. Это находки про текст, а не про код.
DD_SEMGREP_EXCLUDE=${DD_SEMGREP_EXCLUDE:-"*.md"}
# Что скармливать bandit: он умеет только Python.
DD_BANDIT_PATHS=${DD_BANDIT_PATHS:-"services packages"}
# Python, на котором uvx запускает SAST. Не косметика: под 3.9 в окружение
# semgrep приезжает старая opentelemetry-instrumentation, которая импортирует
# pkg_resources, а его в venv от uv нет — semgrep падает на старте. Плюс
# bandit разбирает код модулем ast того интерпретатора, на котором запущен:
# на 3.9 файл с синтаксисом 3.12 не распарсится и уедет в errors, то есть
# будет молча не проверен. Версия та же, на которой работает сам сервис.
DD_SAST_PYTHON=${DD_SAST_PYTHON:-3.12}
# Версии закреплены по той же причине, что trivy и правила YARA: состав
# находок зависит от версии сканера, и плавающая даст скачок в дашборде,
# который будут разбирать как настоящий.
DD_BANDIT_SPEC=${DD_BANDIT_SPEC:-bandit==1.9.4}
DD_SEMGREP_SPEC=${DD_SEMGREP_SPEC:-semgrep==1.176.1}
# Обход ошибки упаковки semgrep. Колесо помечено manylinux_2_34, и сам
# semgrep-core действительно требует glibc 2.34 — но вложенный в него
# libgcc_s.so.1 собран под 2.35. Один файл из двадцати шести. На EL9
# (Oracle/RHEL/Rocky 9, glibc 2.34) движок из-за него не стартует:
# `GLIBC_2.35 not found`. Проверено на 1.164.0, 1.170.0 и 1.176.1 — везде.
#
# Лечится подменой на системную библиотеку: у semgrep-core стоит DT_RUNPATH,
# а не DT_RPATH, а RUNPATH проигрывает LD_PRELOAD. Движку нужен от libgcc
# только символ GCC_3.0 — он есть в любой версии с 2001 года.
#
# Именно LD_PRELOAD, а не LD_LIBRARY_PATH=/lib64: последний утянул бы и
# libstdc++, а системный на EL9 даёт ровно требуемый GLIBCXX_3.4.29, без
# запаса. Подменяем один файл, остальное берётся из колеса.
#
# Нет файла — нет подмены: на macOS и там, где semgrep работает и так,
# переменная не выставляется.
DD_SEMGREP_LIBGCC=${DD_SEMGREP_LIBGCC:-/lib64/libgcc_s.so.1}

SERVICES_ALL="gateway worker bot notifier writer cvdmirror"
TARGETS_DEFAULT="$SERVICES_ALL repo sast"

fail=0
say() { printf '  ok    %s\n' "$1"; }
bad() {
	printf '  СБОЙ  %s\n' "$1"
	fail=1
}

insecure=""
[ "$DD_INSECURE" = "1" ] && insecure="-k"

# ------------------------------------------------------------------ проверки

targets=$*
[ -n "$targets" ] || targets=$TARGETS_DEFAULT

# trivy нужен только под образы и зависимости репозитория. Требовать его на
# прогоне одного SAST — значит не дать запустить SAST там, где trivy не стоит.
need_trivy=0
for t in $targets; do
	[ "$t" = "sast" ] || need_trivy=1
done

echo "DefectDojo: ${DD_URL:-<не задан>}"

command -v curl >/dev/null 2>&1 || bad "curl не найден в PATH"
[ "$need_trivy" = "0" ] || command -v trivy >/dev/null 2>&1 ||
	bad "trivy не найден в PATH"
case "$DD_SBOM_FORMAT" in
cyclonedx | spdx-json) ;;
*) bad "DD_SBOM_FORMAT: ожидается cyclonedx или spdx-json, а не '$DD_SBOM_FORMAT'" ;;
esac
[ -n "$DD_URL" ] || bad "DD_URL пуст — заполните ~/.dd.env"
[ -n "$DD_TOKEN" ] || bad "DD_TOKEN пуст — заполните ~/.dd.env"
[ "$fail" = 0 ] || {
	echo
	echo "Не готово к запуску."
	exit 1
}

# Токен проверяем ДО сканирования: trivy на шести образах идёт минуты, и
# узнавать про 401 после них — обидно.
probe_err=$(mktemp) || exit 1
probe=$(curl -sS $insecure -o /dev/null -w '%{http_code}' \
	-H "Authorization: Token $DD_TOKEN" \
	"$DD_URL/api/v2/product_types/?limit=1" 2>"$probe_err")
case "$probe" in
200) say "API и токен приняты" ;;
401 | 403) bad "API: токен отвергнут (HTTP $probe)" ;;
# 000 — соединение не состоялось: адрес, сеть или сертификат.
000)
	bad "API не отвечает"
	sed 's/^/      /' "$probe_err"
	;;
*) bad "API: неожиданный ответ HTTP $probe" ;;
esac
rm -f "$probe_err"
[ "$fail" = 0 ] || exit 1

# ------------------------------------------------------------------- контекст

if git rev-parse --git-dir >/dev/null 2>&1; then
	commit=$(git rev-parse HEAD)
	branch=$(git rev-parse --abbrev-ref HEAD)
else
	commit=""
	branch=""
fi

if [ -n "$DD_REPORT_DIR" ]; then
	mkdir -p "$DD_REPORT_DIR" || exit 1
	work=$DD_REPORT_DIR
	cleanup=""
else
	work=$(mktemp -d) || exit 1
	cleanup=$work
fi
# Отчёт trivy содержит пути и имена пакетов; на диске ему делать нечего.
trap 'test -n "$cleanup" && rm -rf "$cleanup"' EXIT INT TERM

# --------------------------------------------------------------------- заливка

push() { # продукт service файл scan_type engagement
	product=$1
	service=$2
	report=$3
	scan_type=$4
	engagement=$5

	set -- \
		-F "scan_type=$scan_type" \
		-F "file=@$report" \
		-F "auto_create_context=true" \
		-F "product_type_name=$DD_PRODUCT_TYPE" \
		-F "product_name=$product" \
		-F "engagement_name=$engagement" \
		-F "service=$service" \
		-F "close_old_findings=true" \
		-F "minimum_severity=$DD_MIN_SEVERITY" \
		-F "active=true" \
		-F "verified=false" \
		-F "version=$IMAGE_TAG" \
		-F "scan_date=$(date -u +%Y-%m-%d)"
	[ -n "$commit" ] && set -- "$@" -F "commit_hash=$commit"
	[ -n "$branch" ] && set -- "$@" -F "branch_tag=$branch"

	out=$(curl -sS $insecure -X POST "$DD_URL/api/v2/reimport-scan/" \
		-H "Authorization: Token $DD_TOKEN" \
		-w '\n%{http_code}' "$@" 2>&1)
	code=$(printf '%s' "$out" | tail -n 1)
	body=$(printf '%s' "$out" | sed '$d')

	if [ "$code" != "201" ] && [ "$code" != "200" ]; then
		bad "  $scan_type -> $product: HTTP $code"
		printf '%s\n' "$body" | head -c 400 | sed 's/^/      /'
		return 1
	fi

	# В разных версиях DD поле называется по-разному; берём то, что нашлось.
	test_id=$(printf '%s' "$body" | sed -n 's/.*"test"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
	[ -n "$test_id" ] || test_id=$(printf '%s' "$body" | sed -n 's/.*"test_id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
	if [ -n "$test_id" ]; then
		say "  $scan_type -> $product: $DD_URL/test/$test_id"
	else
		say "  $scan_type -> $product (HTTP $code, id теста не разобран)"
	fi
}

# trivy fs | trivy image — один разбор аргументов на оба режима.
run_trivy() { # режим цель формат файл метка [доп. флаги...]
	mode=$1
	target=$2
	fmt=$3
	out=$4
	label=$5
	shift 5
	if ! trivy "$mode" --quiet --format "$fmt" --output "$out" "$@" "$target" \
		2>"$out.err"; then
		bad "$label: trivy не отработал"
		head -3 "$out.err" | sed 's/^/      /'
		return 1
	fi
	rm -f "$out.err"
	[ -s "$out" ] || {
		bad "$label: trivy вернул пустой отчёт"
		return 1
	}
	say "$label"
}

sbom_scan_type() {
	case "$DD_SBOM_FORMAT" in
	cyclonedx) echo "CycloneDX Scan" ;;
	spdx-json) echo "SPDX Scan" ;;
	esac
}

sbom() { # режим цель продукт service имя-файла метка
	[ "$DD_SBOM" = "1" ] || return 0
	mode=$1
	target=$2
	product=$3
	service=$4
	name=$5
	label=$6
	out="$work/$name.sbom.json"

	if [ "$DD_SBOM_WITH_VULNS" = "1" ] && [ "$DD_SBOM_FORMAT" = "cyclonedx" ]; then
		run_trivy "$mode" "$target" "$DD_SBOM_FORMAT" "$out" "$label" \
			--scanners vuln || return 1
	else
		run_trivy "$mode" "$target" "$DD_SBOM_FORMAT" "$out" "$label" || return 1
	fi
	push "$product" "$service" "$out" "$(sbom_scan_type)" "$DD_SBOM_ENGAGEMENT"
}

# Инструмент с PATH, иначе через uvx. pip в этом репозитории запрещён, а
# тащить bandit и semgrep в uv.lock ради CI — значит поставить их в окружение,
# которое собирает образы.
# uvx впереди PATH намеренно. Инструмент с PATH — это чужая версия на чужом
# интерпретаторе: на раннере ей оказался системный python 3.9, и semgrep не
# стартовал вовсе. uvx даёт закреплённую версию на закреплённом Python, то
# есть один и тот же состав находок локально и в CI.
sast_cmd() { # спецификация имя -> команда запуска или пусто
	if command -v uvx >/dev/null 2>&1; then
		echo "uvx --python $DD_SAST_PYTHON --from $1 $2"
	elif command -v "$2" >/dev/null 2>&1; then
		echo "$2"
	else
		echo ""
	fi
}

# По коду выхода судить нельзя: bandit возвращает 1 на найденных проблемах,
# semgrep — свои коды, и «нашлись уязвимости» неотличимо от «сканер упал».
# Признак успеха — непустой файл отчёта.
run_sast() { # метка файл команда...
	label=$1
	out=$2
	shift 2
	"$@" >"$out.log" 2>&1
	if [ ! -s "$out" ]; then
		bad "$label: отчёт не создан"
		tail -3 "$out.log" 2>/dev/null | sed 's/^/      /'
		return 1
	fi
	rm -f "$out.log"
	say "$label"
}

scan_sast() {
	cmd=$(sast_cmd "$DD_BANDIT_SPEC" bandit)
	if [ -z "$cmd" ]; then
		bad "bandit недоступен — нужен uv (для uvx) или bandit в PATH"
	else
		out="$work/bandit.json"
		# --exit-zero: иначе находки неотличимы от сбоя запуска.
		run_sast "bandit — Python ($DD_BANDIT_PATHS)" "$out" \
			$cmd -r $DD_BANDIT_PATHS -f json -o "$out" --exit-zero &&
			push "vulnscantg-repo" "repo" "$out" "Bandit Scan" "$DD_SAST_ENGAGEMENT"
	fi

	cmd=$(sast_cmd "$DD_SEMGREP_SPEC" semgrep)
	if [ -z "$cmd" ]; then
		bad "semgrep недоступен — нужен uv (для uvx) или semgrep в PATH"
		return 0
	fi
	out="$work/semgrep.json"
	pre=""
	[ -f "$DD_SEMGREP_LIBGCC" ] && pre="env LD_PRELOAD=$DD_SEMGREP_LIBGCC"
	# --metrics=off: с реестровыми правилами semgrep иначе шлёт телеметрию.
	set -- $pre $cmd scan --quiet --metrics=off --json --output "$out"
	# set -f на время разбора списков. Без него shell раскрывает `*.md` по
	# текущему каталогу и подставляет CLAUDE.md README.md ROADMAP.md — то есть
	# исключает три файла в корне вместо всех markdown, и находки из docs/
	# продолжают приходить. Ошибка тихая: команда отрабатывает успешно.
	set -f
	for cfg in $DD_SEMGREP_CONFIG; do set -- "$@" --config "$cfg"; done
	for ex in $DD_SEMGREP_EXCLUDE; do set -- "$@" --exclude "$ex"; done
	set +f
	set -- "$@" .
	packs=$(echo $DD_SEMGREP_CONFIG | wc -w | tr -d " ")
	run_sast "semgrep — $packs наборов правил" "$out" "$@" &&
		push "vulnscantg-repo" "repo" "$out" "Semgrep JSON Report" "$DD_SAST_ENGAGEMENT"
}

scan_image() { # сервис
	svc=$1
	image="$IMAGE_NAMESPACE/vulnscantg-$svc:$IMAGE_TAG"
	report="$work/$svc.json"

	run_trivy image "$image" json "$report" "$svc — уязвимости" \
		--scanners vuln,secret,misconfig || return 1
	push "vulnscantg-$svc" "$svc" "$report" "Trivy Scan" "$DD_ENGAGEMENT" || return 1

	sbom image "$image" "vulnscantg-$svc" "$svc" "$svc" "$svc — SBOM"
}

scan_repo() {
	report="$work/repo.json"

	run_trivy fs . json "$report" "исходники — уязвимости" \
		--scanners vuln,secret,misconfig || return 1
	# Отдельный product: у скана репозитория своя жизнь, и close_old_findings
	# не должен закрывать находки образов, и наоборот.
	push "vulnscantg-repo" "repo" "$report" "Trivy Scan" "$DD_ENGAGEMENT" || return 1

	sbom fs . "vulnscantg-repo" "repo" "repo" "исходники — SBOM"
}

# ----------------------------------------------------------------------- цели

echo
if [ "$need_trivy" = "1" ]; then
	echo "Образы: $IMAGE_NAMESPACE/vulnscantg-*:$IMAGE_TAG   engagement: $DD_ENGAGEMENT"
fi
if [ "$need_trivy" = "1" ] && [ "$DD_SBOM" = "1" ]; then
	if [ "$DD_SBOM_WITH_VULNS" = "1" ] && [ "$DD_SBOM_FORMAT" = "cyclonedx" ]; then
		sbom_note="с уязвимостями"
	else
		sbom_note="только инвентарь — находок в DD не будет"
	fi
	echo "SBOM: $DD_SBOM_FORMAT ($sbom_note)   engagement: $DD_SBOM_ENGAGEMENT"
elif [ "$need_trivy" = "1" ]; then
	echo "SBOM: выключен (DD_SBOM=0)"
fi
echo "Цели: $targets"
echo

for target in $targets; do
	case "$target" in
	repo) scan_repo || true ;;
	sast) scan_sast || true ;;
	*)
		case " $SERVICES_ALL " in
		*" $target "*) scan_image "$target" || true ;;
		*) bad "$target — неизвестная цель (есть: $SERVICES_ALL repo sast)" ;;
		esac
		;;
	esac
done

echo
if [ "$fail" = 0 ]; then
	echo "Готово. Всё залито."
else
	echo "Готово с ошибками — смотрите строки СБОЙ выше."
fi
exit "$fail"
