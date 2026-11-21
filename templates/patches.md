# 20 шаблонов патчей (защита без докера)

Сервисы — локальные процессы/systemd + файлы. Правим код/конфиг прямо на серваке.
**Главное правило:** после КАЖДОГО патча — проверь, что чекер зелёный (сервис принимает и отдаёт флаг). Сломал чекер = красный SLA = минус очки, хуже чем украденный флаг.

> Дисциплина патча: 1) держи сервис под git (см. №20), 2) правь минимально, 3) `systemctl restart <svc>`, 4) проверь локально (`curl 127.0.0.1:<port>`), 5) скажи вслух «пропатчил X». Не работает чекер — `git checkout` назад.

---

## 1. IDOR → проверка владельца
Было: отдаём объект по id без проверки, чей он.
```python
# было:  note = db.get(note_id); return note.text
note = db.get(note_id)
if note.owner != session["user"]:      # добавить проверку прав
    abort(403)
return note.text
```

## 2. Path traversal → нормализация + «клетка»
```python
import os
BASE = "/app/files"
full = os.path.realpath(os.path.join(BASE, user_path))
if not full.startswith(BASE + os.sep):   # не выпускаем за BASE
    abort(400)
```

## 3. SQL-инъекция → параметризованный запрос
```python
# было:  cur.execute("SELECT * FROM n WHERE id='%s'" % x)
cur.execute("SELECT * FROM n WHERE id = ?", (x,))     # sqlite
cur.execute("SELECT * FROM n WHERE id = %s", (x,))    # psycopg/mysql
```

## 4. Command injection → без shell, белый список
```python
# было:  os.system("ping " + host)
import subprocess, re
if not re.fullmatch(r"[A-Za-z0-9.\-]+", host): abort(400)
subprocess.run(["ping", "-c1", host], timeout=3)      # список аргументов, shell=False
```

## 5. SSTI → не рендерить ввод как шаблон
```python
# было:  render_template_string("Hi " + name)
return "Hi " + escape(name)                 # или render_template с {{ name }} как ДАННЫМИ
```

## 6. JWT / auth bypass → нормальная проверка подписи
```python
import jwt
data = jwt.decode(token, SECRET, algorithms=["HS256"])   # запретить alg=none
# SECRET поменять со слабого на длинный случайный; старые токены протухнут — ок
```

## 7. Insecure deserialize → убрать pickle/eval, брать json
```python
# было:  obj = pickle.loads(data)  /  eval(data)
import json
obj = json.loads(data)                       # yaml -> yaml.safe_load
```

## 8. XXE → выключить внешние сущности
```python
from lxml import etree
p = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
tree = etree.fromstring(xml, parser=p)
```

## 9. Debug/stacktrace off (Flask/Django и т.п.)
```python
app.run(host="0.0.0.0", port=5000, debug=False)   # debug=True = RCE через консоль
# Django: DEBUG = False
```

## 10. Убрать утечку исходников (.git, .bak, .env, листинг)
```bash
cd /path/to/service
rm -rf .git *.bak *~ *.swp backup.zip        # НЕ удаляй рабочий код!
# nginx: autoindex off;  location ~ /\.(git|env) { deny all; }
```

## 11. Дефолтные креды → сменить (но сперва проверь чекер)
```bash
# меняем пароль админа/БД. Сначала убедись, НЕ ходит ли чекер под admin/admin!
# если чекер под дефолтом — трогать нельзя, иначе SLA красный.
```

## 12. File upload → белый список расширений/типа
```python
import os
ok = {".png",".jpg",".txt"}
if os.path.splitext(fname)[1].lower() not in ok: abort(400)
fname = os.path.basename(fname)              # срезать пути
```

## 13. Hardcoded key / слабый секрет → ротация
```python
import secrets
SECRET = secrets.token_hex(32)               # заменить зашитый 'secret123'
# если секрет общий с чекером — уточни, иначе чекер отвалится
```

## 14. Backdoor/магический параметр → вырезать
```python
# было:  if request.args.get("debug") == "1": return all_flags()
# просто удалить этот блок целиком. grep по 'debug','backdoor','god','secret_admin'
```

## 15. Mass-assignment → только разрешённые поля
```python
allowed = {"title", "text"}
data = {k: v for k, v in request.args.items() if k in allowed}   # не даём выставить owner/role
```

## 16. Валидация длины/типа ввода
```python
if not isinstance(x, str) or len(x) > 256: abort(400)
```

## 17. nftables — закрыть только служебные порты (НЕ атакующих!)
```
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 22 ip saddr 10.0.0.0/8 accept     # SSH только своей сети
    tcp dport { 80, 443, 5000 } accept          # порты сервисов — открыты всем (и чекеру!)
    ip protocol icmp accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
```
`sudo nft -f /etc/nftables.conf`. Не отрежь себе SSH. **Порт сервиса бить нельзя — там же ходит чекер.**

## 18. L7-фильтр: пускать жюри, резать чужие (все за ОДНИМ IP!)
Все команды и чекер идут с одного прокси-IP → фильтруй по **User-Agent / поведению**, а не по IP.
Сначала разведай UA чекера (`06_traffic.md` §6), потом reverse-proxy перед сервисом:
```nginx
# чекер ходит со стабильным UA — пускаем; подозрительный паттерн эксплойта — 404
location /vuln_endpoint {
    if ($http_user_agent !~* "checker-ua-из-дампа") { return 404; }
    proxy_pass http://127.0.0.1:5000;
}
```
Осторожно: ошибёшься в UA — положишь чекер. Патч кода надёжнее, фильтр — как второй слой.

## 19. WAF-заплатка в самом сервисе (быстро, пока нет нормального патча)
```python
BAD = ["UNION", "../", "{{", "__", "pickle", ";cat", "SYSTEM"]
@app.before_request
def waf():
    raw = (request.query_string or b"").decode(errors="ignore").upper()
    if any(b.upper() in raw for b in BAD): abort(400)
# ВНИМАНИЕ: прогони чекер — вдруг он сам шлёт что-то похожее. Это временно.
```

## 20. git-workflow патчей (откат за секунды)
```bash
cd /path/to/service
git init && git add -A && git commit -m round0   # ДО игры, пока сервис «ванильный»
# патчим, рестартим, проверяем чекер:
systemctl restart <svc>; curl -s 127.0.0.1:5000/ | head
git add -A && git commit -m "patch idor"
# чекер покраснел? откат:
git checkout -- . && systemctl restart <svc>
```

---

## Проверка «чекер зелёный» после патча (делать ВСЕГДА)
1. `systemctl restart <svc>` (или как сервис запускается).
2. `curl -s http://127.0.0.1:<port>/` — сервис отвечает?
3. Пройди сам сценарий чекера руками (регистрация → запись → чтение).
4. Жди 1–2 раунда, смотри скорборд: SLA должен быть зелёным.
5. Красный → `git checkout` назад и думай заново. **Лучше дыра, чем мёртвый сервис.**
