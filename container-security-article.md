# Безопасность Linux-контейнеров: где ломается изоляция и как это увидеть

**Филипп, scrock_**

Привет, Хабр!

Контейнеры давно перестали быть экзотикой. Сегодня на них работает почти всё - от пет-проектов до production-систем крупных компаний. Но за удобством и скоростью развёртывания скрывается набор механизмов Linux, который часто воспринимают как «магическую коробку».

Пока всё работает, о границах этой коробки можно не задумываться. Когда приложение оказывается скомпрометировано, контейнер получает лишние права или процесс видит ресурсы хоста, понимание устройства изоляции становится критичным.

В этой статье разберём безопасность Linux-контейнеров без иллюзий. Сначала посмотрим, что на самом деле происходит после запуска контейнера, затем соберём отдельный лабораторный хост и воспроизведём несколько типовых ошибок конфигурации. Каждую ситуацию проведём по одной схеме:

1. Запускаем небезопасную конфигурацию
2. Выполняем действие из контейнера
3. Находим его следы в Docker, cgroups и Falco
4. Включаем защиту
5. Повторяем проверку и сравниваем результат.

Цель - не собрать коллекцию эффектных команд, а связать атаку, наблюдаемый сигнал и конкретную меру защиты.

> **Важно:** все эксперименты выполняются только в отдельной одноразовой виртуальной машине. Не запускайте лабораторные конфигурации на рабочем ноутбуке, сервере или узле Kubernetes.

## Границы статьи

Здесь рассматриваются Linux-контейнеры на одном хосте с Docker Engine и cgroups v2. Kubernetes, admission-политики, service account, сетевые политики и безопасность control plane заслуживают отдельного разбора: если добавить их сейчас, придётся пожертвовать либо точностью, либо практикой.

Supply chain тоже затронем только как один из способов первоначального доступа. Проверка подписей, SBOM, provenance и защита CI/CD — самостоятельная тема.

## От `chroot` к контейнерам

Идея дать процессу отдельное представление файловой системы появилась задолго до Docker. Системный вызов [`chroot(2)`](https://man7.org/linux/man-pages/man2/chroot.2.html) меняет каталог, который процесс воспринимает как `/`. Но документация Linux прямо подчёркивает: `chroot` меняет только один компонент разрешения путей и не предназначен для полноценной песочницы.

Следующим шагом стали [пространства имён](https://man7.org/linux/man-pages/man7/namespaces.7.html), или namespaces. Они оборачивают глобальные ресурсы ядра так, чтобы группа процессов видела собственное представление этих ресурсов:

- `mnt` — точки монтирования;
- `pid` — дерево процессов;
- `net` — интерфейсы, маршруты, firewall и сокеты;
- `uts` — hostname и domain name;
- `ipc` — System V IPC и POSIX message queues;
- `user` — UID, GID и capabilities;
- `cgroup` — представление иерархии control groups;
- `time` — некоторые системные часы.

Namespaces отвечают прежде всего на вопрос: **что видит процесс?** Они не определяют, сколько памяти он может занять и сколько CPU использовать.

Для учёта и ограничения ресурсов используются [control groups](https://man7.org/linux/man-pages/man7/cgroups.7.html), или cgroups. Первая реализация вошла в Linux 2.6.24; современная единая иерархия cgroups v2 позволяет ограничивать и наблюдать память, CPU, число процессов и другие ресурсы. Это не файловая и не процессная изоляция: cgroups решают задачу доступности и учёта.

Права суперпользователя Linux разделяет на отдельные [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html). Этот механизм существует с Linux 2.2. Вместо полного набора полномочий root процессу можно оставить, например, только `CAP_NET_BIND_SERVICE`. На практике некоторые capabilities остаются слишком широкими: особенно осторожно следует относиться к `CAP_SYS_ADMIN`.

[Seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) решает другую задачу: фильтрует системные вызовы и их аргументы. Он не понимает бизнес-логику приложения, не управляет файловыми путями и не заменяет AppArmor или SELinux. Seccomp лишь уменьшает доступную процессу поверхность ядра.

Наконец, Linux Security Modules добавляют контроль доступа к объектам ядра. Например, Docker на совместимом Ubuntu-хосте применяет профиль [`docker-default`](https://docs.docker.com/engine/security/apparmor/) для AppArmor, если пользователь не отключил или не заменил его.

Все эти механизмы существовали независимо друг от друга. Контейнерные runtime собрали их в воспроизводимый способ запуска процессов.

## Как контейнер устроен на самом деле

Начнём с главного: контейнер — не маленькая виртуальная машина. У него нет собственного ядра. Внутри работает обычный Linux-процесс, использующий то же ядро, что и процессы хоста.

Типичный путь запуска Docker-контейнера выглядит так:

```text
registry
   │
   ▼
OCI image ──► Docker Engine ──► containerd ──► runc ──► процесс приложения
                                                      │
                                                      ▼
Linux kernel: namespaces · cgroups · capabilities · seccomp · LSM
```

Схема намеренно упрощена, но показывает главное: образ, runtime и запущенный процесс — разные сущности.

### Образ

Согласно [OCI Image Specification](https://specs.opencontainers.org/image-spec/config/), образ — это упорядоченный набор изменений root filesystem и конфигурация запуска: entrypoint, аргументы, переменные окружения и другие параметры. Образ не выполняется и сам по себе ничего не изолирует.

После запуска слои образа объединяются в root filesystem контейнера, а поверх них обычно добавляется writable layer. Конкретная реализация зависит от snapshotter или storage driver.

### Runtime

Docker Engine подготавливает конфигурацию и передаёт выполнение нижележащим компонентам. В типичной установке Docker участвуют containerd и `runc`. Низкоуровневый runtime создаёт окружение процесса по [OCI Runtime Specification](https://specs.opencontainers.org/runtime-spec/runtime/): настраивает namespaces, mounts, cgroup, capabilities, seccomp, окружение и команду запуска.

После старта приложение обращается не к Docker, а к общему ядру через системные вызовы. Поэтому уязвимость ядра или runtime принципиально отличается от ошибки в приложении внутри контейнера.

### Где проходит граница безопасности

У контейнера нет одной стены, которую можно «включить». Граница складывается из нескольких независимых ограничений:

| Механизм | Что ограничивает | Чего не делает |
|---|---|---|
| Namespaces | Видимость процессов, сети, mounts и других ресурсов | Не ограничивают потребление памяти и CPU |
| Cgroups | Ресурсы и их учёт | Не запрещают чтение файлов и системные вызовы |
| Capabilities | Привилегированные операции | Не фильтруют обычные syscalls и файловые пути |
| Seccomp | Системные вызовы и отдельные аргументы | Не является файловой или сетевой политикой |
| AppArmor/SELinux | Доступ процесса к объектам | Не заменяют лимиты ресурсов |
| User namespace | Отображение UID/GID и область capabilities | Не исправляет опасные mounts или открытый runtime API |

Слабость одного слоя не всегда означает выход на хост. Опасными становятся комбинации: writable bind mount плюс избыточные права, общий PID namespace плюс возможность `ptrace`, открытый runtime socket плюс полномочия rootful daemon.

## Модель угроз

Чтобы не смешивать разные сценарии, разделим первоначальный доступ и цель атакующего.

| Первоначальный доступ | Пример | Следующая цель |
|---|---|---|
| Уязвимость приложения | RCE, небезопасная десериализация, загрузка исполняемого файла | Секреты, сеть, соседние сервисы, хост |
| Вредоносный или скомпрометированный образ | Бэкдор в entrypoint или зависимости | Данные и полномочия окружения запуска |
| Ошибка конфигурации | `--privileged`, опасный bind mount, лишние capabilities | Расширение доступа за границы приложения |
| Доступ к API runtime | Docker socket или удалённый Docker API | Создание новых контейнеров с другими правами |
| Уязвимость ядра или runtime | Ошибка в Linux, containerd или runc | Нарушение границы между контейнером и хостом |

В практической части исходной точкой будет выполнение команд внутри контейнера. Неважно, оказался там атакующий через RCE или вредоносный образ: нас интересует, что позволяет и чего не позволяет конфигурация runtime.

## Лабораторный стенд

### Почему нужна отдельная VM

Часть экспериментов намеренно ослабляет ограничения контейнера. В лаборатории будет доступ к bind mounts, Docker API и расширенным capabilities. Ошибка в команде или незавершённый эксперимент не должны затронуть основную систему.

Виртуальная машина также делает результаты воспроизводимыми. Docker Desktop и WSL используют дополнительные слои виртуализации, из-за чего пути mounts, сеть, ядро и доступность eBPF могут отличаться от обычного Linux-хоста.

### Рекомендуемая конфигурация

| Компонент | Минимум для стенда | Рекомендуется |
|---|---:|---:|
| Архитектура | x86_64/amd64 | x86_64/amd64 |
| vCPU | 2 | 4 |
| RAM | 4 ГБ | 8 ГБ |
| Диск | 25 ГБ | 40 ГБ, thin provisioned |
| Сеть | NAT | NAT без входящих пробросов |
| Guest OS | Ubuntu Server 24.04 LTS | актуальный point release 24.04 LTS |

Canonical указывает для Ubuntu Server 24.04 LTS рекомендуемый минимум 3 ГБ RAM и 25 ГБ диска; дополнительная память здесь нужна для нескольких контейнеров и Falco. Системные требования опубликованы в [документации Ubuntu Server](https://ubuntu.com/server/docs/reference/installation/system-requirements/).

Скачайте ISO [Ubuntu Server 24.04 LTS](https://ubuntu.com/download/server) с официального сайта. В качестве гипервизора подойдёт VirtualBox, VMware Workstation/Fusion, KVM/libvirt или Hyper-V. Важен не конкретный продукт, а полноценное Linux-ядро внутри VM и возможность сделать snapshot.

Перед экспериментами:

1. установите Ubuntu Server;
2. выберите NAT для сетевого адаптера;
3. установите обновления;
4. перезагрузите VM;
5. создайте snapshot `clean-os`.

```bash
sudo apt update
sudo apt full-upgrade -y
sudo reboot
```

Не используйте bridged networking без необходимости и не публикуйте лабораторные порты в домашнюю или корпоративную сеть.

### Базовые инструменты

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git jq make dialog
```

Проверим ядро и cgroups:

```bash
uname -a
stat -fc %T /sys/fs/cgroup
findmnt -t cgroup2
```

Для единой иерархии последняя команда должна показать `cgroup2`. Ubuntu Server 24.04 использует cgroups v2 по умолчанию.

### Установка Docker Engine

Используем официальный apt-репозиторий Docker, а не пакет `docker.io` из Ubuntu и не установочный shell-скрипт. Актуальная процедура и поддерживаемые версии Ubuntu перечислены в [документации Docker Engine](https://docs.docker.com/engine/install/ubuntu/).

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
```

Проверим установку:

```bash
sudo systemctl --no-pager --full status docker
sudo docker run --rm hello-world
sudo docker version
sudo docker compose version
sudo docker info --format 'cgroup driver={{.CgroupDriver}}; cgroup version={{.CgroupVersion}}'
```

В статье команды Docker выполняются через `sudo`. Членство в группе `docker` [предоставляет пользователю root-level privileges](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user) и не является обычным «разрешением запускать контейнеры». Это отдельная граница доверия, которую нет смысла скрывать в статье о безопасности.

### Установка Falco

[Falco](https://falco.org/docs/) получает события ядра и сопоставляет их с правилами. Для стенда установим его на хост VM и выберем modern eBPF. Этот driver встроен в Falco и обычно работает на ядрах Linux 5.8 и новее; точные требования зависят от доступных возможностей ядра. Подробности есть в [документации источника kernel events](https://falco.org/docs/concepts/event-sources/kernel/).

Добавим официальный репозиторий:

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt update
sudo apt install -y falco
```

В диалоге установки выберите **Modern eBPF**. Автоматическое обновление ruleset можно включить, но для воспроизводимости финальной версии стенда правила и версии следует зафиксировать в репозитории.

Проверим сервис:

```bash
sudo systemctl --no-pager --full status falco-modern-bpf.service
sudo journalctl -u falco-modern-bpf.service -n 50 --no-pager
```

Отдельно сохраним версии компонентов. Этот вывод понадобится при разборе результатов и вопросов читателей:

```bash
uname -r
sudo docker version
sudo containerd --version
sudo runc --version
sudo falco --version
```

После успешной установки создайте snapshot `lab-ready`.

<!--
Редакторская задача перед публикацией:
1. Добавить ссылку на репозиторий стенда.
2. Зафиксировать теги и digest всех образов.
3. Добавить проверочный скрипт, который валидирует Ubuntu, cgroups v2, Docker и Falco.
4. Сохранить пример ожидаемого вывода setup-check.
-->

## Практика 0. Контейнер глазами ядра

Начнём без эксплуатации. Наша задача — увидеть механизмы изоляции, которые Docker настроил для обычного контейнера.

На хосте посмотрим пространства имён PID 1:

```bash
sudo ls -l /proc/1/ns
```

Теперь выведем namespace identifiers, cgroup, capabilities и seccomp mode внутри контейнера:

```bash
sudo docker run --rm ubuntu:24.04 sh -c '
  echo "== namespaces =="
  for ns in cgroup ipc mnt net pid time user uts; do
    printf "%-8s " "$ns"
    readlink "/proc/self/ns/$ns" 2>/dev/null || echo "not available"
  done

  echo "== cgroup =="
  cat /proc/self/cgroup

  echo "== process security =="
  grep -E "^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status
'
```

У обычного rootful Docker-контейнера mount, PID, network, IPC и UTS namespaces должны отличаться от хоста. User namespace, напротив, по умолчанию может совпадать с начальным user namespace хоста, если не включены user namespace remapping или rootless mode.

Поле `Seccomp: 2` означает filter mode, но не раскрывает состав фильтра. `CapEff` представлен битовой маской; позже декодируем её и сравним с контейнером, у которого удалены все capabilities.

### Что этот опыт доказывает

Команда не обнаруживает «отдельную ОС». Она показывает один процесс, включённый сразу в несколько механизмов ядра. Именно их конфигурацию мы будем менять дальше.

<!--
Для репозитория:
- добавить scripts/inspect-container.sh;
- сохранить эталонный вывод хоста и контейнера;
- показать docker inspect для SecurityOpt, CapDrop, CgroupnsMode и mounts;
- не утверждать, что namespace ID обязаны иметь конкретные числовые значения.
-->

## Практика 1. Контейнер без ресурсных границ

По умолчанию контейнер не получает жёстких ограничений CPU и памяти и может использовать ресурсы, доступные планировщику хоста. Это прямо указано в [документации Docker о resource constraints](https://docs.docker.com/engine/containers/resource_constraints/).

В этой лаборатории сравним две конфигурации одного workload:

- без memory и PID limits;
- с ограничениями памяти, CPU и количества процессов.

### Что измеряем

- `docker stats`;
- состояние и exit code контейнера;
- `memory.current`, `memory.max` и `memory.events` в cgroup v2;
- `pids.current`, `pids.max` и `pids.events`;
- события OOM в journal ядра;
- сообщения Falco, если для стенда добавлено соответствующее правило.

### Ожидаемый результат

Без лимита workload конкурирует с процессами хоста. С hard memory limit ядро ограничивает конкретную cgroup и может завершить процесс внутри неё. С PID limit новые процессы перестают создаваться после достижения границы, не исчерпывая общесистемный PID space.

> В небезопасном варианте нагрузку всё равно нужно ограничить временем и выполнять только внутри VM. Цель — показать отсутствие границы, а не добиться зависания хоста.

<!--
Добавить практику:
1. Собственный минимальный образ resource-hog без сторонних stress-образов.
2. compose.vulnerable.yaml без limits.
3. compose.hardened.yaml с memory, cpus и pids_limit.
4. Таймаут и trap для гарантированной остановки нагрузки.
5. Команды поиска cgroup контейнера на systemd-host.
6. Ожидаемые memory.events и pids.events.
7. make lab-01 / make clean-01.
-->

## Практика 2. Лишние права и опасные монтирования

Bind mount связывает путь хоста с путём внутри контейнера. По умолчанию такой mount доступен на запись, поэтому процесс контейнера может изменять данные хоста. Docker отдельно предупреждает об этом в документации по [bind mounts](https://docs.docker.com/engine/storage/bind-mounts/).

Эксперимент состоит из трёх этапов:

1. контейнер получает writable mount специально созданного каталога `lab-host-data`;
2. процесс меняет контрольный файл, а Falco фиксирует операцию;
3. mount становится read-only, контейнер запускается без capabilities и от непривилегированного UID.

Мы не монтируем `/`, `/etc`, `/proc`, `/sys`, `/dev` и домашний каталог пользователя. Для демонстрации достаточно искусственного файла внутри VM. Риск определяется не ценностью тестового файла, а тем, что запись произошла через границу root filesystem контейнера.

### Отдельно о `--privileged`

Флаг `--privileged` нельзя описывать как одну дополнительную capability. Docker выдаёт контейнеру все capabilities, доступ к устройствам, writable `/sys`, writable cgroup mounts и ослабляет другие механизмы защиты. В [документации `docker run`](https://docs.docker.com/reference/cli/docker/container/run/#privileged) такой контейнер прямо не считается безопасной песочницей.

Для статьи достаточно сравнить конфигурацию и наблюдаемые ограничения. Выполнять запись на реальные block devices или монтировать корневой раздел хоста не требуется.

<!--
Добавить практику:
1. Генерация lab-host-data/marker.txt внутри VM.
2. Уязвимый compose с rw bind mount.
3. Falco rule на изменение marker или каталога стенда.
4. Hardened compose: read_only, tmpfs /tmp, user 10001:10001,
   cap_drop ALL, no-new-privileges, bind mount :ro.
5. Повтор команды: ожидаемый Permission denied / Read-only file system.
6. docker inspect до и после.
-->

## Практика 3. Docker socket как управляющий интерфейс

`/var/run/docker.sock` — Unix socket API Docker daemon. Если передать его контейнеру, процесс внутри получает возможность отправлять daemon те же запросы, что и локальный Docker CLI. Это не магический «выход через файл» и не ошибка namespaces: контейнеру сознательно передали управляющий интерфейс.

Для обычного rootful Docker последствия определяются полномочиями daemon. Клиент API может запросить создание нового контейнера с другими mounts, устройствами и security options. Поэтому доступ к socket следует считать административным доступом к Docker-хосту. Та же граница доверия описана Docker в разделе [Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface).

В лаборатории пройдём минимальную цепочку:

1. обнаружение socket внутри контейнера;
2. чтение версии Docker API;
3. создание через API отдельного демонстрационного контейнера;
4. наблюдение операции через `docker events` и Falco;
5. удаление socket из конфигурации и повторная проверка.

Все действия ограничиваются VM и тестовым каталогом. Контейнер не получает mount корня хоста.

### Что является защитой

Основное исправление — не передавать socket приложению. `:ro` у bind mount не делает Docker API read-only: это файловый режим mount, а не фильтр HTTP-методов. Если интеграции действительно нужен Docker API, требуются отдельный доверенный компонент, минимальный набор операций, аутентификация и аудит.

<!--
Добавить практику:
1. Минимальный собственный client-образ с curl/jq и pinned digest.
2. Только безопасные API-вызовы к стендовому daemon.
3. docker events с фильтрами create/start/die/destroy.
4. Falco rule на обращение к docker.sock из обычного workload.
5. Cleanup, удаляющий только ресурсы с label проекта.
6. Явно проверить rootful Docker; rootless вынести в отдельное примечание.
-->

## Практика 4. Seccomp, capabilities и `no-new-privileges`

Эти три механизма часто складывают в один список, хотя они проверяют разные свойства процесса:

- capabilities отвечают, обладает ли поток конкретным привилегированным правом;
- seccomp решает, разрешено ли выполнить системный вызов;
- `no-new-privileges` запрещает процессу получать новые привилегии через `execve`, например за счёт setuid или file capabilities.

Сначала посмотрим текущую конфигурацию через `/proc/self/status` и `docker inspect`. Затем запустим один и тот же тестовый бинарник в четырёх режимах:

1. конфигурация Docker по умолчанию;
2. `--cap-drop ALL`;
3. `--security-opt no-new-privileges=true`;
4. собственный seccomp profile, запрещающий только выбранный для опыта syscall.

Важно не доказывать, что «seccomp спасает от всего». Правильный вывод уже: конкретная операция была остановлена конкретным механизмом, а приложение сохранило необходимую функциональность.

Не стоит фиксировать в тексте число syscalls, запрещённых Docker по умолчанию: профиль меняется между версиями и архитектурами. Актуальная логика и список находятся в [документации default seccomp profile](https://docs.docker.com/engine/security/seccomp).

<!--
Добавить практику:
1. Написать маленький test helper на C или Go с одним syscall на сценарий.
2. Не зависеть от наличия утилит в базовом образе.
3. Выводить errno и exit code.
4. Хранить custom-seccomp.json рядом с compose.
5. Добавить smoke-test полезной функции приложения после включения профиля.
6. Показать Falco event отдельно от preventive control.
-->

## Мониторинг: событие не равно инциденту

Falco анализирует поток событий ядра и применяет к нему правила. Простейшее правило может заметить shell, запущенный внутри контейнера:

```yaml
- rule: Interactive shell in lab container
  desc: Detect a shell started in a container from this lab
  condition: >
    spawned_process and
    container.id != host and
    proc.name in (bash, sh) and
    container.name startswith "container-security-lab-"
  output: >
    Shell in lab container
    (user=%user.name container=%container.name
    process=%proc.name parent=%proc.pname command=%proc.cmdline)
  priority: NOTICE
  tags: [container, process, lab]
```

Это учебное правило, а не готовая production-политика. Shell может быть нормальной частью entrypoint или диагностики, поэтому без контекста такой сигнал даёт ложные срабатывания. Синтаксис, поля и примеры правил описаны в [документации Falco](https://falco.org/docs/concepts/rules/) и [официальных примерах](https://falco.org/docs/reference/rules/examples/).

Для каждого правила в стенде нужно ответить на четыре вопроса:

1. Какое поведение мы хотим обнаружить?
2. Какие легитимные процессы ведут себя так же?
3. Какие поля позволят сузить правило без привязки к случайному PID?
4. Что должен сделать оператор после срабатывания?

Хорошее сообщение содержит как минимум контейнер, образ, пользователя, процесс, родительский процесс и командную строку. Для сетевых событий нужны направление, адрес и порт; для файловых — путь и тип операции.

### Что Falco не решает

Falco не заменяет preventive controls. Он не добавляет resource limits, не закрывает Docker socket, не исправляет образ и не запрещает `--privileged`, пока вы отдельно не построили механизм реакции. Runtime detection полезен тогда, когда у сигнала есть владелец, контекст и сценарий ответа.

<!--
Добавить практику:
1. monitoring/falco/rules.d/lab_rules.yaml.
2. falco -V или falco --validate для проверки правил согласно текущей версии.
3. Для каждого lab — alert fixture и expected output.
4. Тесты правил через falco-event-generator или сохранённые события,
   если это совместимо с выбранной версией Falco.
5. Таблицу false positives и исключений.
-->

## Как выглядит усиленная конфигурация

Ни один флаг не является универсальным профилем безопасности. Но для обычного stateless-приложения отправной точкой может быть такой набор:

```bash
sudo docker run --rm \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --memory 256m \
  --cpus 0.50 \
  --pids-limit 128 \
  IMAGE
```

Это шаблон для обсуждения, а не команда, которую следует копировать для любого приложения. Возможно, программе нужен writable каталог, определённая capability или другой объём памяти. Требование нужно добавить точечно и объяснить, а не отключать весь защитный слой.

Отдельный резерв безопасности даёт user namespace: root внутри контейнера можно отобразить в непривилегированный UID хоста. Docker описывает этот режим в документации по [`userns-remap`](https://docs.docker.com/engine/security/userns-remap/). Ещё один вариант — [rootless mode](https://docs.docker.com/engine/security/rootless/), при котором без root работает и daemon, и контейнеры. У обоих подходов есть ограничения совместимости, поэтому их следует проверять на реальном workload.

## Почему наличие CVE — другой класс проблемы

Ошибочная конфигурация и уязвимость runtime могут привести к похожему результату, но требуют разных мер защиты.

При опасном bind mount runtime выполняет разрешённую конфигурацию. При уязвимости `runc` или ядра реализация нарушает ожидаемую границу. Например, [GHSA-xr7r-f8xq-vfvv](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) описывает несколько вариантов container breakout в `runc`, связанных с утечкой файловых дескрипторов и доступом к host filesystem.

Такой кейс полезно разобрать на схеме, но не следует выдавать его за «уязвимый Docker-образ». Уязвимый компонент находится на хосте; образ может быть лишь способом передать подготовленную конфигурацию или содержимое. Для защиты нужны обновление runtime, сокращение прав запуска недоверенных образов и дополнительные слои изоляции.

<!--
Перед публикацией кейса:
1. Выбрать один уже исправленный advisory.
2. Зафиксировать affected/patched versions из первичного источника.
3. Не размещать рабочий breakout против актуальных систем.
4. Показать цепочку предпосылок, последствия, исправление и возможную телеметрию.
5. Отделить доказанные факты advisory от собственных выводов.
-->

## Проверочный чек-лист

Перед запуском контейнера проверьте следующее:

- образ получен из доверенного источника и закреплён digest;
- приложение запускается не от root либо root отображён через user namespace;
- удалены все capabilities, которые не нужны приложению;
- не используется `--privileged`;
- включён `no-new-privileges`;
- root filesystem доступен только для чтения, а writable paths перечислены явно;
- bind mounts минимальны и по возможности read-only;
- Docker, containerd и CRI sockets не передаются приложению;
- `/proc`, `/sys`, `/dev` и корень хоста не монтируются без обоснования;
- настроены memory, CPU и PID limits;
- применяется seccomp profile;
- AppArmor или SELinux действительно включён, а не только указан в конфигурации;
- секреты не встроены в образ и не переданы обычными environment variables без оценки риска;
- сетевой ingress и egress ограничены на уровне, который поддерживает среда;
- события runtime поступают в мониторинг, а у правил есть сценарии реакции;
- ядро, Docker Engine, containerd и runc регулярно обновляются.

Полезными внешними ориентирами для проверки архитектуры остаются [NIST SP 800-190 Application Container Security Guide](https://csrc.nist.gov/pubs/sp/800/190/final), официальная [модель безопасности Docker Engine](https://docs.docker.com/engine/security/) и [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).

## Заключение

Контейнер не является отдельной машиной. Это процесс с ограниченным представлением системы, ограниченными ресурсами и урезанными полномочиями, но с общим ядром хоста.

Из этого следуют три практических вывода.

Во-первых, безопасность контейнера нельзя свести к одному инструменту. Seccomp не заменяет AppArmor, Falco не заменяет resource limits, а сканер образов не заметит опасный mount при запуске.

Во-вторых, ошибки редко существуют поодиночке. Лишняя capability, writable mount и доступный runtime API усиливают друг друга.

В-третьих, защита должна проверяться тем же действием, которое демонстрировало проблему. Если после изменения конфигурации мы не повторили опыт, то у нас есть намерение, но ещё нет результата.

Именно поэтому контейнерную безопасность стоит строить как цикл: определить границу, воспроизвести нарушение, увидеть сигнал, применить ограничение и проверить его снова.

## Основные источники

### Linux

- [`chroot(2)`](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [`cgroups(7)`](https://man7.org/linux/man-pages/man7/cgroups.7.html)
- [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html)

### OCI и Docker

- [OCI Image Specification](https://specs.opencontainers.org/image-spec/config/)
- [OCI Runtime Specification](https://specs.opencontainers.org/runtime-spec/runtime/)
- [Docker Engine security](https://docs.docker.com/engine/security/)
- [Docker default seccomp profile](https://docs.docker.com/engine/security/seccomp)
- [Docker AppArmor profiles](https://docs.docker.com/engine/security/apparmor/)
- [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)
- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)

### Стенд и мониторинг

- [Ubuntu Server system requirements](https://ubuntu.com/server/docs/reference/installation/system-requirements/)
- [Установка Docker Engine на Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Falco documentation](https://falco.org/docs/)
- [Falco kernel event source](https://falco.org/docs/concepts/event-sources/kernel/)
- [Falco rules](https://falco.org/docs/concepts/rules/)

---

<!--
Финальная редактура перед публикацией:

- Проверить все команды на чистой VM из snapshot clean-os.
- Зафиксировать дату проверки, версии Docker/Falco и digest образов.
- Каждой команде дать ожидаемый результат и критерий успеха.
- Убедиться, что make clean удаляет только ресурсы проекта по label/name.
- Удалить редакторские HTML-комментарии или оставить их только в рабочей ветке.
- Добавить диаграммы только там, где они объясняют границу лучше текста.
- Сделать скриншоты Falco минимальными: событие плюс два-три важных поля.
- Не называть misconfiguration container escape, если переход границы не доказан.
- Не использовать абсолютные формулировки «полная безопасность» и «защищает от всех атак».
-->
