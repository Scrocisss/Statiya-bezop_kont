# Безопасность Linux-контейнеров: где ломается изоляция и как это увидеть

**Филипп, scrock_**

Привет, Хабр!

Контейнеры давно перестали быть экзотикой. Сегодня они используются повсюду - от личных проектов до промышленных систем крупных компаний. При этом контейнер нередко воспринимают как «магическую коробку», хотя его изоляцию обеспечивают вполне конкретные механизмы Linux. Пока всё работает, о границах этой коробки можно не задумываться. Когда приложение оказывается скомпрометировано, контейнер получает лишние права или процесс видит ресурсы хоста, понимание устройства изоляции становится критичным.

В этой статье разберём, как устроена изоляция Linux-контейнеров и какие события помогают обнаружить опасную активность внутри них. Сначала посмотрим, что происходит при запуске контейнера, затем соберём лабораторный стенд и воспроизведём несколько сценариев, которые становятся возможны из-за ошибок конфигурации. Каждый сценарий исследуем по одной схеме:   

1. Запускаем контейнер с намеренно ослабленной конфигурацией.
2. Воспроизводим сценарий эксплуатации.
3. Собираем системные события и выделяем признаки атаки.
4. Настраиваем правило обнаружения и проверяем его на атакующем и штатном сценариях.
5. Устраняем ошибку конфигурации, если атаку можно предотвратить.
6. Повторяем эксперимент и сравниваем результат.

Целью статьи является не собрать коллекцию эффектных команд, а последовательно воспроизвести атаку, обнаружить её по телеметрии, проверить качество детекта и по возможности устранить причину.

**Важно:** все эксперименты выполняются только в отдельной одноразовой виртуальной машине.

## Границы статьи

Мы сосредоточимся на Linux-контейнерах, запущенных через Docker на одном сервере. Это позволит последовательно разобрать их изоляцию, воспроизвести несколько атак и настроить мониторинг, не переключаясь между разными средами. Кластеры Kubernetes и защиту их управляющих компонентов оставим для отдельной статьи. Там появляются собственные механизмы управления доступом, сетью и запуском контейнеров, которые требуют самостоятельной практической части. Также мы не будем подробно разбирать весь путь контейнерного образа - от сборки и хранения до запуска на сервере. В этой статье достаточно учитывать, что скомпрометированный образ может стать исходной точкой атаки.

## От chroot к контейнерам

Идея дать процессу отдельное представление файловой системы появилась задолго до Docker. Системный вызов [`chroot`](https://man7.org/linux/man-pages/man2/chroot.2.html) назначает выбранный каталог корнем для процесса и его потомков. Однако документация Linux подчёркивает, что этот механизм лишь меняет начальную точку разрешения абсолютных путей и сам по себе не создаёт полноценную песочницу.

Следующим шагом стали [`namespaces`](https://man7.org/linux/man-pages/man7/namespaces.7.html) или пространства имён. Они позволяют группе процессов видеть собственное представление глобальных ресурсов ядра:

- Пространство точек монтирования ([`mnt`](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)) изолирует набор подключённых файловых систем. Благодаря этому процессы могут видеть собственные точки монтирования, отличающиеся от точек монтирования на хосте.
- Пространство идентификаторов процессов ([`pid`](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)) изолирует нумерацию и видимость процессов. Внутри него процессы получают собственные идентификаторы и не видят процессы из родительского пространства имён.
- Сетевое пространство ([`net`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)) изолирует сетевой стек. К нему относятся сетевые интерфейсы, сетевые адреса, таблицы маршрутизации, правила межсетевого экрана и пространство сетевых портов.
- Пространство системных имён ([`uts`](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html)) изолирует имя узла. Благодаря этому контейнер может иметь собственное имя, не изменяя имя хоста.
- Пространство межпроцессного взаимодействия ([`ipc`](https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html)) изолирует общую память, семафоры и очереди сообщений System V, а также очереди сообщений POSIX.
- Пространство пользователей ([`user`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)) изолирует идентификаторы пользователей, идентификаторы групп и связанные с ними привилегии. Пользователь с нулевым идентификатором (UID 0) внутри этого пространства может соответствовать непривилегированному пользователю на хосте.
- Пространство групп управления ресурсами ([`cgroup`](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)) изолирует представление иерархии таких групп (`cgroups`). Процесс видит только отведённую ему часть этой иерархии, однако само пространство имён не устанавливает ресурсные ограничения.
- Пространство времени ([`time`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)) изолирует показания отдельных системных часов. Процессы могут иметь собственные значения монотонного времени и времени, отсчитываемого с момента загрузки системы.

Пространства имён определяют, какие ресурсы системы видит процесс. Ограничение памяти и процессорного времени в их задачи не входит.

Для учёта и ограничения ресурсов используются [`cgroups`](https://man7.org/linux/man-pages/man7/cgroups.7.html) или группы управления ресурсами. Первая версия этого механизма вошла в Linux 2.6.24. Современная единая иерархия второй версии `cgroups v2` позволяет учитывать и ограничивать потребление памяти, процессорного времени, количество процессов и другие ресурсы. Группы управления ресурсами не скрывают файлы или процессы. Их задача заключается в учёте ресурсов и защите хоста от их исчерпания.

Linux разделяет полномочия суперпользователя на отдельные [`capabilities`](https://man7.org/linux/man-pages/man7/capabilities.7.html) или привилегии. Этот механизм существует с Linux 2.2. Вместо полного набора прав суперпользователя процессу можно выдать только необходимую привилегию. Например, `CAP_NET_BIND_SERVICE` позволяет привязать сетевую службу к порту с номером меньше 1024. Некоторые привилегии охватывают слишком много операций. Особенно осторожно следует относиться к `CAP_SYS_ADMIN`, поскольку эта привилегия открывает доступ к широкому набору функций системного администрирования.

[`seccomp`](https://docs.kernel.org/userspace-api/seccomp_filter.html) или механизм ограничения системных вызовов определяет, какие обращения к ядру разрешены процессу и с какими аргументами. Он не анализирует логику приложения, не управляет доступом к файловым путям и не заменяет такие средства контроля доступа, как AppArmor или SELinux. Его задача заключается в сокращении набора системных вызовов, через которые процесс может взаимодействовать с ядром.

Дополнительный уровень защиты создают [`Linux Security Modules`](https://docs.kernel.org/admin-guide/LSM/index.html), что и переводится как модули безопасности Linux. Они применяют политики доступа к файлам, процессам и другим объектам системы. На хосте с включённым AppArmor Docker по умолчанию использует профиль [`docker-default`](https://docs.docker.com/engine/security/apparmor/), если пользователь не отключил или не заменил его.

Все эти механизмы развивались независимо друг от друга. [`container runtimes`](https://specs.opencontainers.org/runtime-spec/runtime/) (средства запуска контейнеров) объединяют их при создании процесса и каждый раз воспроизводят заданную конфигурацию изоляции.

## Как контейнер устроен на самом деле

Начнём с главного. Контейнер - не маленькая виртуальная машина. Для Linux это один процесс или группа процессов, которым ядро показывает ограниченное представление системы. У них могут быть собственные дерево процессов, сеть и файловая система, но системные вызовы по-прежнему обрабатывает ядро хоста. Поэтому контейнер изолирует процессы, а не запускает отдельную операционную систему. В [документации Docker](https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-a-container/) он также определяется прежде всего как изолированный процесс.

### Контейнер и виртуальная машина

Разница между ними заключается в уровне, на котором создаётся изоляция. Гипервизор предоставляет [виртуальной машине](https://docs.kernel.org/virt/kvm/index.html) виртуальные процессоры, память и устройства, после чего она загружает полноценную гостевую операционную систему со своим ядром. Контейнер не имитирует отдельный компьютер и не загружает ещё одну операционную систему. Вместо этого среда выполнения запускает процессы на хосте и ограничивает их с помощью пространств имён, контрольных групп, отдельных полномочий, фильтров системных вызовов и модулей безопасности. Благодаря этому контейнеры обычно требуют меньше ресурсов и запускаются быстрее, однако ядро остаётся общей границей безопасности. Ошибка в приложении, уязвимость среды выполнения и уязвимость ядра дают атакующему разные возможности, поэтому сам факт запуска в контейнере ещё не означает надёжную изоляцию. На практике обе технологии часто используют вместе, когда виртуальная машина становится хостом для нескольких контейнеров.

### От образа к процессу

После команды `docker run` [Docker Engine](https://docs.docker.com/get-started/docker-overview/) ищет указанный образ в локальном хранилище. Если его там нет, движок загружает образ из реестра. Сам образ ещё не является контейнером. Это доступный только для чтения шаблон, состоящий из манифеста, конфигурации и слоёв файловой системы. Конфигурация содержит параметры, необходимые для запуска приложения. Формат этих компонентов описывает [спецификация образа OCI](https://github.com/opencontainers/image-spec/blob/main/spec.md).

Затем Docker Engine обращается к [`containerd`](https://containerd.io/), который подготавливает файловую систему контейнера и координирует его жизненный цикл. [`containerd-shim`](https://github.com/containerd/containerd/blob/main/docs/runtime-v2.md) принимает команды от `containerd` и вызывает низкоуровневую среду выполнения [`runc`](https://github.com/opencontainers/runc). Она применяет подготовленную OCI-конфигурацию через интерфейсы ядра и запускает процесс приложения. После запуска shim продолжает обслуживать ввод и вывод процесса, отслеживает его состояние и передаёт код завершения.

![Путь от образа контейнера до процесса приложения](./images/docker-runtime-architecture.png)

После запуска приложение продолжает работать как один или несколько обычных процессов Linux. `runc` создаёт заданную конфигурацией среду, но не становится частью контейнера или его отдельным ядром. Границу между процессами контейнера и хостом формирует совокупность механизмов Linux. Эту границу мы и будем проверять в практической части.

## Где проходит граница изоляции

На схеме контейнер выглядит как отдельный блок, однако в Linux нет единой стены между ним и хостом. Граница складывается из настроек процессов. Пространства имён меняют видимость ресурсов, группы управления ресурсами задают пределы потребления, привилегии разрешают отдельные административные операции, фильтр сокращает набор разрешённых системных вызовов, а AppArmor или SELinux ограничивают доступ к объектам системы.

Файловая система контейнера тоже не является самостоятельным диском. Она собирается из слоёв образа, изменяемого слоя и подключённых хранилищ. [Подключение каталога хоста (`bind mount`)](https://docs.docker.com/engine/storage/bind-mounts/) проводит путь через границу контейнера и делает этот каталог доступным изнутри. Если разрешена запись, изменения сразу отражаются на хосте.

Та же логика действует для других ресурсов. Контейнер можно подключить к пространству процессов или сети хоста, предоставить ему устройства или добавить привилегии. Флаг [`--privileged`](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities) выдаёт контейнеру все привилегии, открывает доступ к устройствам и значительно ослабляет политики AppArmor или SELinux. Контейнер не превращается в виртуальную машину. Его процессы лишь получают больше способов воздействовать на ядро и устройства хоста.

Отдельное место занимает сокет Docker. По умолчанию клиент обращается к Docker Engine через `/var/run/docker.sock`. Получив доступ к сокету, процесс может отправлять команды службе Docker. В обычном режиме служба работает от имени суперпользователя (`root`), поэтому доступ к ней фактически даёт административные полномочия на хосте. Например, через неё можно создать контейнер с подключённой корневой файловой системой хоста. Документация Docker отдельно предупреждает, что [управлять службой должны только доверенные пользователи](https://docs.docker.com/engine/security/).

Граница контейнера определяется не названием образа и не самим фактом использования Docker. Она зависит от всей конфигурации запуска. Опасность часто возникает не из-за одного параметра, а из-за сочетания нескольких условий. Например, доступная для записи файловая система хоста становится значительно опаснее вместе с лишними привилегиями, а открытый сокет Docker превращает компрометацию приложения в возможность создавать новые контейнеры с другими настройками.

## Модель угроз

В практической части будем считать, что атакующий уже выполняет команды внутри контейнера от имени приложения. Точкой входа могла стать командная инъекция, небезопасная десериализация, загрузка исполняемого файла или вредоносный образ. Мы проверим, какие возможности даёт конфигурация контейнера и какие следы оставляют действия атакующего.

В начале каждого эксперимента у атакующего нет командного доступа к хосту по протоколу SSH, учётной записи администратора и прямого управления Docker Engine. В конфигурацию намеренно добавляется одна ошибка. Так результат можно связать с конкретной настройкой, а не с неопределённым набором привилегий.

### Что защищаем

- Файловую систему и процессы хоста;
- Данные приложения и подключённых хранилищ;
- Секреты, токены и учётные данные;
- Соседние контейнеры и их сетевое окружение;
- Доступность процессора, памяти и пространства процессов;
- Саму систему мониторинга и сохранность её событий.

### Что считаем развитием атаки

Сам факт выполнения команды внутри уже скомпрометированного контейнера не равен выходу на хост. Развитием атаки будем считать доступ к ресурсам, которые не требуются приложению. К ним относятся чтение секретов, изменение файлов хоста, управление Docker Engine, вход в пространства имён хоста, воздействие на соседние контейнеры и исчерпание общих ресурсов.

Уязвимость ядра или средства запуска тоже может нарушить изоляцию, но непубличные и нестабильные способы эксплуатации в эту статью не войдут. Практика будет основана на ошибках конфигурации и штатных интерфейсах Linux и Docker. Такие сценарии проще воспроизвести, а их результат легче проверить.

### Откуда берётся первоначальный доступ

Основным сценарием станет уязвимость приложения. Для него подготовим небольшой контейнер с намеренной командной инъекцией. Она позволит контролируемо выполнять команды от имени веб-приложения и сравнивать такую активность с действиями администратора через `docker exec`.

Скомпрометированный образ рассмотрим только как другой способ оказаться внутри контейнера. Перечень его компонентов (`SBOM`), проверка подписей, подтверждение происхождения сборки и защита системы сборки и доставки приложений (`CI/CD`) остаются за пределами статьи. Доступ к программному интерфейсу Kubernetes (`API`) и атаки на управляющие компоненты кластера также не входят в выбранную модель.

## Лабораторный стенд

### Требования к физическому хосту

Для стенда понадобится компьютер с аппаратной виртуализацией и гипервизором. Подойдут KVM с libvirt, VMware Workstation, VMware Fusion, VirtualBox или Hyper-V... Для размещения всего стенда на одном физическом хосте желательно иметь не менее 16 ГБ оперативной памяти и около 100 ГБ свободного места.

Лабораторная виртуальная машина отделяет уязвимые контейнеры от основной системы и позволяет сохранить её состояние перед экспериментами. Если конфигурация будет повреждена, стенд можно вернуть к заранее созданному снимку.

### Виртуальная машина

Для воспроизводимости используем Ubuntu Server 24.04. Установочный образ доступен на [официальной странице выпуска](https://releases.ubuntu.com/24.04/). В стенде используется файл `ubuntu-24.04.4-live-server-amd64.iso`.

Для запуска всех компонентов на одной виртуальной машине выделим следующие ресурсы.

- 6 виртуальных процессоров.
- 12 ГБ оперативной памяти.
- 100 ГБ динамически расширяемого диска.
- Сетевой адаптер в режиме сетевого моста (для доступа к Kibana).
- Минимальная установка Ubuntu Server без графической оболочки.

Если Elasticsearch и Kibana работают на другой машине, объём оперативной памяти лабораторной виртуальной машины можно уменьшить до 4 ГБ. Ресурсы отдельного узла мониторинга в этом случае рассчитываются отдельно.

Для связи двух виртуальных машин лучше добавить им сетевые адаптеры, подключённые к отдельной изолированной сети гипервизора. Через эту сеть Falcosidekick сможет передавать события в Elasticsearch, а физический хост - обращаться к Kibana. Уязвимый стенд не следует подключать сетевым мостом непосредственно к рабочей локальной сети.

### Компоненты стенда

В состав лабораторного стенда войдут:

- Docker Engine и Docker Compose для запуска лабораторных контейнеров.
- Falco с современным драйвером на основе eBPF для получения событий ядра и проверки правил.
- Falcosidekick для передачи событий Falco.
- Elasticsearch для хранения и поиска событий.
- Kibana для анализа и визуализации.
- Уязвимое приложение и вспомогательные контейнеры из репозитория статьи.

Стенд можно собрать двумя способами.

1. Разместить Docker, Falco, Falcosidekick, Elasticsearch и Kibana на одной виртуальной машине с 12 ГБ оперативной памяти.
2. Оставить Docker, Falco и Falcosidekick на лабораторной машине с 4 ГБ памяти, а Elasticsearch и Kibana вынести на отдельный узел мониторинга (или вовсе отказаться от мониторинга).

![Два варианта размещения компонентов лабораторного стенда](./images/monitoring-layout.png)

Falco устанавливается непосредственно в гостевую операционную систему и получает события её ядра. Falcosidekick, Elasticsearch и Kibana можно запустить через Docker Compose. Размещение всех компонентов на одном узле удобно для лаборатории, но не является примером промышленной архитектуры. В рабочей среде события обычно отправляют на отдельный узел, чтобы после компрометации контейнерного хоста их нельзя было удалить вместе с локальными данными.

### Подготовка системы и установка базовых инструментов

После установки Ubuntu обновим систему.

```bash
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y ca-certificates curl gnupg git jq make dialog
sudo reboot
```

Проверим версию ядра и используемую иерархию групп управления ресурсами:

```bash
uname -a && stat -fc %T /sys/fs/cgroup && findmnt -t cgroup2
```

<details>
<summary>Развернуть вывод команды</summary>

  ```bash
scrock_@scrockcontainers:~$ uname -a && stat -fc %T /sys/fs/cgroup && findmnt -t cgroup2

Linux scrockcontainers 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu
Sep 24 11:33:16 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux

cgroup2fs

TARGET        SOURCE FSTYPE OPTIONS
/sys/fs/cgroup
              cgroup2
                     cgroup
                     rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_r
```

</details>


Команда `stat` должна вывести `cgroup2fs`, а `findmnt` должна показать подключённую файловую систему `cgroup2`.

После перезагрузки создадим в гипервизоре снимок виртуальной машины с именем `clean-os`. Это будет контрольная точка с чистой обновлённой системой, к которой можно вернуться после неудачной установки или эксперимента. Сам снимок создаётся средствами гипервизора.

После этого можно переходить к установке Docker, Falco и остальных компонентов стенда.

### Установка Docker Engine

Docker установим из [официального репозитория](https://docs.docker.com/engine/install/ubuntu/).

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

После установки проверим службу и запустим тестовый контейнер:

```bash
sudo systemctl --no-pager --full status docker
sudo docker run --rm hello-world
sudo docker version
sudo docker compose version
sudo docker info --format \
  'cgroup driver={{.CgroupDriver}}; cgroup version={{.CgroupVersion}}'
```

<details>
<summary>Развернуть вывод команды</summary>

  ```bash
scrock_@scrockcontainers:~$ sudo docker run --rm hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
4f55086f7dd0: Pull complete 
d5e71e642bf5: Download complete 
Digest: sha256:11a3eb1597e864c51b3f56733cb2e8a90bf0c284bfc05f9444d81c558bc848aa
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (amd64)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/

scrock_@scrockcontainers:~$ sudo docker version
Client: Docker Engine - Community
 Version:           29.9.1
 API version:       1.56
 Go version:        go1.26.9
 Git commit:        dfc520d
 Built:             Wed Oct 14 18:32:55 2026
 OS/Arch:           linux/amd64
 Context:           default

Server: Docker Engine - Community
 Engine:
  Version:          29.9.1
  API version:      1.56 (minimum version 1.40)
  Go version:       go1.26.9
  Git commit:       b26fb77
  Built:            Wed Oct 14 18:32:55 2026
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          v2.4.2
  GitCommit:        b7a25261e029d68978bbf290df0a62fc819b3c51
 runc:
  Version:          1.5.2
  GitCommit:        v1.5.2-0-g29dd3dc2
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0
scrock_@scrockcontainers:~$ sudo docker compose version
Docker Compose version v5.6.0
scrock_@scrockcontainers:~$ sudo docker info --format \
  'cgroup driver={{.CgroupDriver}}; cgroup version={{.CgroupVersion}}'
cgroup driver=systemd; cgroup version=2
```

</details>

Команды Docker в статье выполняются через `sudo`. Добавление пользователя в группу `docker` не выдаёт ограниченное разрешение на запуск контейнеров. Docker прямо предупреждает, что [членство в этой группе предоставляет полномочия суперпользователя (`root`)](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user).

### Установка Falco

[Falco](https://falco.org/docs/) получает события ядра и проверяет их по набору правил. Начиная с версии 0.38, Falco по умолчанию использует современный драйвер на основе eBPF. В настройках он называется `modern_ebpf`. Для стенда выберем его явно.

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt update
sudo env FALCO_FRONTEND=noninteractive \
  FALCO_DRIVER_CHOICE=modern_ebpf \
  apt install -y falco
```

Проверим состояние службы:

```bash
sudo systemctl --no-pager --full status falco-modern-bpf.service
sudo journalctl -u falco-modern-bpf.service -n 50 --no-pager
sudo falco --version
```

<details>
<summary>Развернуть вывод команды</summary>

  ```bash
scrock_@scrockcontainers:~$ sudo systemctl --no-pager --full status falco-modern-bpf.service
● falco-modern-bpf.service - Falco: Container Native Runtime Security with modern ebpf
     Loaded: loaded (/usr/lib/systemd/system/falco-modern-bpf.service; enabled; preset: enabled)
     Active: active (running) since Fri 2026-10-16 21:34:04 UTC; 10s ago
       Docs: https://falco.org/docs/
   Main PID: 3138 (falco)
      Tasks: 19 (limit: 13913)
     Memory: 63.1M (peak: 81.5M)
        CPU: 10.140s
     CGroup: /system.slice/falco-modern-bpf.service
             └─3138 /usr/bin/falco -o engine.kind=modern_ebpf

Oct 16 21:34:05 scrockcontainers falco[3138]: Loading rules from:
Oct 16 21:34:05 scrockcontainers falco[3138]:    /etc/falco/falco_rules.yaml | schema validation: ok
Oct 16 21:34:05 scrockcontainers falco[3138]:    /etc/falco/falco_rules.local.yaml | schema validation: none
Oct 16 21:34:05 scrockcontainers falco[3138]: The chosen syscall buffer dimension is: 8388608 bytes (8 MBs)
Oct 16 21:34:05 scrockcontainers falco[3138]: Starting health webserver with threadiness 6, listening on 0.0.0.0:8765
Oct 16 21:34:05 scrockcontainers falco[3138]: Loaded event sources: syscall
Oct 16 21:34:05 scrockcontainers falco[3138]: Enabled event sources: syscall
Oct 16 21:34:05 scrockcontainers falco[3138]: Opening 'syscall' source with modern BPF probe.
Oct 16 21:34:05 scrockcontainers falco[3138]: One ring buffer every '2' CPUs.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: Trying to open the right engine!
scrock_@scrockcontainers:~$ sudo journalctl -u falco-modern-bpf.service -n 50 --no-pager
Oct 16 21:34:04 scrockcontainers systemd[1]: Started falco-modern-bpf.service - Falco: Container Native Runtime Security with modern ebpf.
Oct 16 21:34:04 scrockcontainers falco[3138]: Falco version: 0.45.0 (x86_64)
Oct 16 21:34:04 scrockcontainers falco[3138]: Falco initialized with configuration files:
Oct 16 21:34:04 scrockcontainers falco[3138]:    /etc/falco/config.d/engine-kind-falcoctl.yaml | schema validation: ok
Oct 16 21:34:04 scrockcontainers falco[3138]:    /etc/falco/config.d/falco.container_plugin.yaml | schema validation: ok
Oct 16 21:34:04 scrockcontainers falco[3138]:    /etc/falco/falco.yaml | schema validation: ok
Oct 16 21:34:04 scrockcontainers falco[3138]: System info: Linux version 6.8.0-147-generic (buildd@lcy02-amd64-081) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026
Oct 16 21:34:05 scrockcontainers falco[3138]: Loaded plugin 'container@0.7.4' from file /usr/share/falco/plugins/libcontainer.so
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'podman' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/podman/podman.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'docker' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/var/run/docker.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'cri' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/containerd/containerd.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/crio/crio.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/k3s/containerd/containerd.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/host-containerd/containerd.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'containerd' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: * enabled container runtime socket at '/run/host-containerd/containerd.sock'
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'lxc' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'libvirt_lxc' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: container: Enabled 'bpm' container engine.
Oct 16 21:34:05 scrockcontainers falco[3138]: Loading rules from:
Oct 16 21:34:05 scrockcontainers falco[3138]:    /etc/falco/falco_rules.yaml | schema validation: ok
Oct 16 21:34:05 scrockcontainers falco[3138]:    /etc/falco/falco_rules.local.yaml | schema validation: none                                                  
Oct 16 21:34:05 scrockcontainers falco[3138]: The chosen syscall buffer dimension is: 8388608 bytes (8 MBs)
Oct 16 21:34:05 scrockcontainers falco[3138]: Starting health webserver with threadiness 6, listening on 0.0.0.0:8765
Oct 16 21:34:05 scrockcontainers falco[3138]: Loaded event sources: syscall
Oct 16 21:34:05 scrockcontainers falco[3138]: Enabled event sources: syscall
Oct 16 21:34:05 scrockcontainers falco[3138]: Opening 'syscall' source with modern BPF probe.
Oct 16 21:34:05 scrockcontainers falco[3138]: One ring buffer every '2' CPUs.
Oct 16 21:34:05 scrockcontainers falco[3138]: [libs]: Trying to open the right engine!
scrock_@scrockcontainers:~$ sudo falco --version
Fri Oct 16 21:34:26 2026: Falco version: 0.45.0 (x86_64)
Fri Oct 16 21:34:26 2026: Falco initialized with configuration files:
Fri Oct 16 21:34:26 2026:    /etc/falco/config.d/engine-kind-falcoctl.yaml | schema validation: ok
Fri Oct 16 21:34:26 2026:    /etc/falco/config.d/falco.container_plugin.yaml | schema validation: ok
Fri Oct 16 21:34:26 2026:    /etc/falco/falco.yaml | schema validation: ok
Fri Oct 16 21:34:26 2026: System info: Linux version 6.8.0-147-generic (buildd@lcy02-amd64-081) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026
Falco version: 0.45.0
Libs version:  0.26.0
Plugin API:    3.12.0
Engine:        0.65.0
Driver:
  API version:    11.0.0
  Schema version: 4.3.0
  Default driver: 11.0.0+driver
```

</details>

Актуальные варианты установки и имена служб приведены в [документации Falco](https://falco.org/docs/installation/).

### Elasticsearch, Kibana и Falcosidekick

Falco уже получает события ядра и проверяет их по правилам, но его журнал неудобен для поиска и сравнения экспериментов. Добавим три компонента. [`Falcosidekick`](https://github.com/falcosecurity/falcosidekick) примет уведомления Falco по протоколу HTTP и передаст их в Elasticsearch. Elasticsearch сохранит события, а Kibana позволит искать их и строить представления. Все три компонента запустим на лабораторной машине через Docker Compose.

В стенде используются Elasticsearch и Kibana версии `9.5.5`, а также Falcosidekick версии `2.35.0`. Версии Elasticsearch и Kibana совпадают полностью, как требует [документация Elastic](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/installing-elasticsearch). Контейнерные образы загружаются через зеркало Яндекса `cr.yandex/mirror`, поэтому его адрес указан непосредственно в файле Compose. Для Elasticsearch и Kibana используются официальные образы Docker Hub, сопровождаемые командой Elastic.

Сначала подготовим параметр ядра, необходимый Elasticsearch для работы с отображаемыми в память файлами. Для современных версий Elastic рекомендует значение `1048576` для [`vm.max_map_count`](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/vm-max-map-count).

```bash
echo 'vm.max_map_count=1048576' | \
  sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
sysctl vm.max_map_count
```

<details>
<summary>Развернуть вывод команды</summary>

  ```bash
scrock_@scrockcontainers:~$ echo 'vm.max_map_count=1048576' | \
  sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
sysctl vm.max_map_count
vm.max_map_count=1048576
* Applying /usr/lib/sysctl.d/10-apparmor.conf ...
* Applying /etc/sysctl.d/10-bufferbloat.conf ...
* Applying /etc/sysctl.d/10-console-messages.conf ...
* Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
* Applying /etc/sysctl.d/10-kernel-hardening.conf ...
* Applying /etc/sysctl.d/10-magic-sysrq.conf ...
* Applying /etc/sysctl.d/10-map-count.conf ...
* Applying /etc/sysctl.d/10-network-security.conf ...
* Applying /etc/sysctl.d/10-ptrace.conf ...
* Applying /etc/sysctl.d/10-zeropage.conf ...
* Applying /usr/lib/sysctl.d/50-pid-max.conf ...
* Applying /etc/sysctl.d/99-elasticsearch.conf ...
* Applying /usr/lib/sysctl.d/99-protect-links.conf ...
* Applying /etc/sysctl.d/99-sysctl.conf ...
* Applying /etc/sysctl.conf ...
kernel.apparmor_restrict_unprivileged_userns = 1
net.core.default_qdisc = fq_codel
kernel.printk = 4 4 1 7
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
kernel.kptr_restrict = 1
kernel.sysrq = 176
vm.max_map_count = 1048576
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
kernel.yama.ptrace_scope = 1
vm.mmap_min_addr = 65536
kernel.pid_max = 4194304
vm.max_map_count = 1048576
fs.protected_fifos = 1
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
vm.max_map_count = 1048576
```

</details>


Ожидаемое значение:

```text
vm.max_map_count = 1048576
```

Создадим отдельный каталог для компонентов мониторинга.

```bash
mkdir -p ~/container-security-lab/monitoring
cd ~/container-security-lab/monitoring
```

В файл `compose.yaml` поместим следующую конфигурацию.

```yaml
name: container-security-monitoring

services:
  elasticsearch:
    image: cr.yandex/mirror/elasticsearch:9.5.5
    container_name: lab-elasticsearch
    restart: unless-stopped
    environment:
      discovery.type: single-node
      xpack.security.enabled: "false"
    mem_limit: 4g
    ports:
      - "127.0.0.1:9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    healthcheck:
      test:
        - CMD-SHELL
        - >-
          curl --silent --fail
          'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s'
          >/dev/null
      interval: 10s
      timeout: 10s
      retries: 12
      start_period: 60s
    networks:
      - monitoring

  kibana:
    image: cr.yandex/mirror/kibana:9.5.5
    container_name: lab-kibana
    restart: unless-stopped
    environment:
      ELASTICSEARCH_HOSTS: '["http://elasticsearch:9200"]'
      SERVER_NAME: lab-kibana
    mem_limit: 2g
    ports:
      - "0.0.0.0:5601:5601"
    depends_on:
      elasticsearch:
        condition: service_healthy
    networks:
      - monitoring

  falcosidekick:
    image: cr.yandex/mirror/falcosecurity/falcosidekick:2.35.0
    container_name: lab-falcosidekick
    restart: unless-stopped
    environment:
      ELASTICSEARCH_HOSTPORT: http://elasticsearch:9200
      ELASTICSEARCH_INDEX: falco
      ELASTICSEARCH_SUFFIX: daily
      ELASTICSEARCH_FLATTENFIELDS: "true"
      ELASTICSEARCH_CREATEINDEXTEMPLATE: "true"
      ELASTICSEARCH_NUMBEROFSHARDS: "1"
      ELASTICSEARCH_NUMBEROFREPLICAS: "0"
    mem_limit: 256m
    ports:
      - "127.0.0.1:2801:2801"
    depends_on:
      elasticsearch:
        condition: service_healthy
    networks:
      - monitoring

networks:
  monitoring:
    name: container-security-monitoring

volumes:
  elasticsearch-data:
    name: container-security-elasticsearch-data
```

Elasticsearch работает в режиме одного узла, поэтому для индексов Falco создаётся один основной сегмент без резервной копии. Постоянный том сохраняет события после перезапуска контейнера. Ограничения памяти не позволяют компонентам мониторинга занять всю оперативную память лабораторной машины.

Встроенная проверка подлинности Elasticsearch в этом стенде отключена намеренно. Elasticsearch и Falcosidekick доступны только внутри виртуальной машины через порты `9200` и `2801`. Порт Kibana `5601` опубликован на сетевых интерфейсах виртуальной машины, чтобы открыть её с физического компьютера. Поэтому сетевой адаптер стенда должен быть подключён к изолированной сети гипервизора, а не к рабочей локальной сети. Открывать Kibana без проверки подлинности в недоверенной сети нельзя. Такая конфигурация предназначена только для лаборатории и не подходит для промышленной эксплуатации.

Проверим синтаксис файла, загрузим образы и запустим компоненты.

```bash
sudo docker compose config --quiet
sudo docker compose pull
sudo docker compose up -d --wait
sudo docker compose ps
```

В выводе `docker compose ps` Elasticsearch должен иметь состояние `healthy`, а Kibana и Falcosidekick — состояние `running`. Первый запуск может занять несколько минут.

Убедимся, что каждый компонент отвечает.

```bash
curl -fsS 'http://127.0.0.1:9200/_cluster/health?pretty'
curl -fsS 'http://127.0.0.1:5601/api/status' | \
  jq -r '.status.overall.level'
curl -fsS 'http://127.0.0.1:2801/healthz' && \
  echo 'Falcosidekick: OK'
```

Elasticsearch должен вернуть сведения о кластере, Kibana — состояние `available`, а проверка Falcosidekick должна завершиться строкой `Falcosidekick: OK`. Если компонент не запустился, посмотрим последние сообщения его контейнера.

```bash
sudo docker compose logs --tail=100 elasticsearch
sudo docker compose logs --tail=100 kibana
sudo docker compose logs --tail=100 falcosidekick
```

После успешной загрузки сохраним фактические идентификаторы образов. Они позволяют проверить, что при повторении стенда используется то же содержимое, даже если содержимое тега в реестре изменится.

```bash
sudo docker image inspect \
  cr.yandex/mirror/elasticsearch:9.5.5 \
  cr.yandex/mirror/kibana:9.5.5 \
  cr.yandex/mirror/falcosecurity/falcosidekick:2.35.0 \
  --format '{{index .RepoDigests 0}}'
```

#### Проверка передачи событий в Elasticsearch

Сначала проверим участок между Falcosidekick и Elasticsearch без участия Falco. Служебный адрес `/test` создаёт тестовое событие и отправляет его во все настроенные приёмники.

```bash
curl -fsS -X POST 'http://127.0.0.1:2801/test' && \
  echo 'Тестовое событие отправлено'
```

Falcosidekick создаёт ежедневные индексы с именами вида `falco-ГГГГ.ММ.ДД`. Проверим появление индекса и количество документов в нём.

```bash
curl -fsS 'http://127.0.0.1:9200/_cat/indices/falco-*?v'
curl -fsS 'http://127.0.0.1:9200/falco-*/_count?pretty'
```

Если индекс не появился, сначала проверим журнал Falcosidekick.

```bash
sudo docker compose logs --tail=100 falcosidekick
```

#### Подключение Falco

Теперь направим в Falcosidekick настоящие уведомления Falco. Сначала сохраним исходную конфигурацию.

```bash
sudo cp --no-clobber \
  /etc/falco/falco.yaml \
  /etc/falco/falco.yaml.before-falcosidekick
sudoedit /etc/falco/falco.yaml
```

В существующем файле найдём указанные параметры и приведём их к следующему виду. Добавлять второй блок `http_output` не нужно.

```yaml
json_output: true
json_include_output_property: true

http_output:
  enabled: true
  url: "http://127.0.0.1:2801/"
```

Falco будет формировать уведомления в формате JSON и отправлять их на локальный порт Falcosidekick. Проверим конфигурацию до перезапуска службы.

```bash
sudo falco --dry-run
```

Если проверка не обнаружила ошибок, перезапустим службу с современным драйвером eBPF и посмотрим её состояние.

```bash
sudo systemctl restart falco-modern-bpf.service
sudo systemctl --no-pager --full status falco-modern-bpf.service
```

Для контрольной проверки запустим интерактивную оболочку в короткоживущем контейнере.

```bash
sudo docker run --rm -it cr.yandex/mirror/alpine:3.22 sh
```

Внутри контейнера выполним `whoami`, а затем завершим оболочку командой `exit`. Стандартное правило Falco должно зафиксировать запуск терминальной оболочки в контейнере. Посмотрим события, полученные после проверки.

```bash
sudo journalctl \
  -u falco-modern-bpf.service \
  --since '2 minutes ago' \
  --no-pager

curl -fsS 'http://127.0.0.1:9200/falco-*/_count?pretty'
```

В журнале Falco и в индексе Elasticsearch должно появиться новое событие. Так мы отдельно проверили оба участка цепочки — передачу от Falco к Falcosidekick и запись из Falcosidekick в Elasticsearch.

#### Просмотр событий в Kibana

Узнаем адрес виртуальной машины в изолированной сети гипервизора.

```bash
ip -br address
```

С физического компьютера откроем в браузере адрес `http://<адрес_виртуальной_машины>:5601`. Например, если лабораторный интерфейс получил адрес `192.168.56.10`, Kibana будет доступна по адресу `http://192.168.56.10:5601`.

После появления первого события создадим [представление данных](https://www.elastic.co/docs/explore-analyze/find-and-organize/data-views/create-data-view), которое свяжет интерфейс Kibana с индексами Falco.

```bash
curl -fsS -X POST \
  'http://127.0.0.1:5601/api/data_views/data_view' \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d '{
    "data_view": {
      "id": "falco-events",
      "name": "Falco events",
      "title": "falco-*",
      "timeFieldName": "time"
    },
    "override": true
  }' | jq
```

В разделе `Discover` выберем представление `Falco events`. В нём должны отображаться как служебная проверка Falcosidekick, так и уведомление, созданное после запуска оболочки в контейнере.

#### Контрольная точка `lab-ready`

Перед созданием снимка выполним итоговую проверку.

```bash
sudo systemctl is-active docker
sudo systemctl is-active falco-modern-bpf.service
sudo docker compose ps
curl -fsS 'http://127.0.0.1:9200/_cluster/health?pretty'
curl -fsS 'http://127.0.0.1:9200/falco-*/_count?pretty'
curl -fsS 'http://127.0.0.1:5601/api/status' | \
  jq -r '.status.overall.level'
```

Docker и Falco должны иметь состояние `active`, контейнеры должны быть запущены, Elasticsearch должен отвечать, в индексе должен находиться хотя бы один документ, а состояние Kibana должно быть `available`.

После проверки корректно выключим виртуальную машину.

```bash
sudo poweroff
```

Когда гостевая система полностью остановится, создадим в гипервизоре снимок `lab-ready`. В нём уже будут установлены Docker и Falco, загружены контейнерные образы, сохранена конфигурация мониторинга и проверена передача событий от Falco до Kibana. К этой точке можно возвращаться перед каждым практическим сценарием.





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
