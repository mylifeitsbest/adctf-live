# A/D CTF — боевой комплект (InnoCTF Junior, ForcAD)

Этот репозиторий клонируем на каждую боевую машину и работаем прямо отсюда.
**Мы полные новички — всё разжёвано.** Не понятно — открывай [00_how_it_works.md](00_how_it_works.md).

```bash
git clone https://github.com/mylifeitsbest/adctf-live.git
```

> Два репо: **adctf-kit** — подготовка на вечер (чеклист); **adctf-live** (этот) — боевой, для игры.

## Читать по порядку
0. [BATTLE.md](BATTLE.md) — **держать открытым всю игру**: факты с открытия, тайминг, боевой цикл, «что делать прямо сейчас», план подготовки на 3 часа.
1. [START_HERE.md](START_HERE.md) — первые 40 минут по минутам, кто что делает.
   - [FIRST_40_MIN.md](FIRST_40_MIN.md) — **если страшно трогать сервак**: те же шаги за руку, с защитой от залочивания и сбросом пароля.
2. [00_how_it_works.md](00_how_it_works.md) — что такое A/D, на пальцах.

## Все файлы
Гайды:
- [BATTLE.md](BATTLE.md) — боевой гайд на все 7 часов + подготовка за 3 часа
- [START_HERE.md](START_HERE.md) — план первых 40 минут
- [00_how_it_works.md](00_how_it_works.md) — как устроена игра
- [01_setup.md](01_setup.md) — настройка машин + SSH с нуля
- [02_defense.md](02_defense.md) — защита без докера
- [03_find_vulns.md](03_find_vulns.md) — как искать уязвимости
- [04_exploit.md](04_exploit.md) — как писать эксплойты
- [05_patch.md](05_patch.md) — как чинить
- [06_traffic.md](06_traffic.md) — перехват трафика, Tulip, реплей
- [07_roles.md](07_roles.md) — роли общей таблицей
- [cheatsheet.md](cheatsheet.md) — шпаргалка команд
- [resources.md](resources.md) — ссылки от оргов + учебные репо

Шаблоны (копипаст):
- [templates/sploits.md](templates/sploits.md) — 20 шаблонов эксплойтов/скриптов
- [templates/patches.md](templates/patches.md) — 20 шаблонов патчей

Ферма и скрипты:
- [farm/README.md](farm/README.md) — ferma флагов (DestructiveFarm, без докера)
- [scripts/sploit_template.py](scripts/sploit_template.py) — шаблон эксплойта
- [scripts/submit_min.py](scripts/submit_min.py) — запасной сабмиттер
- [scripts/attack_data.py](scripts/attack_data.py) — тянет attack_data
- [scripts/capture.sh](scripts/capture.sh) — захват трафика
- [scripts/backup.sh](scripts/backup.sh) — бэкап сервиса
- [scripts/portaudit.sh](scripts/portaudit.sh) — аудит портов

## Железо: 6 ноутов
- 1 Ubuntu = vulnbox (наши сервисы, защищаем, заходим по SSH).
- 5 Kali = рабочие машины (атака + анализ).
- Докера нет, всё локально. Интернет только через прокси, GET.

## Факты про флаги (ForcAD, с открытия)
- Формат: `[A-Z0-9]{31}=`. Живёт 5 раундов (~10 мин). Раунд ~2 мин. Параметры дефолтные: hardness 10, score 3500.
- По 2 флага **на каждую уязвимость** в сервис за раунд (3 дыры → 6 флагов/раунд).
- attack_data во ВСЕХ сервисах: `http://<host>/api/client/attack_data` (в веб-морде её нет). Сабмит по TCP (в ферме).
- **Один прокси-IP на всех** (команды + чекер): по IP не фильтруешь, только по User-Agent/поведению. Интернет — только GET.
- Сервис упал и пересоздан с нуля → ферма ~5 раундов пустая (нет свежих флагов). Не дёргай сервис зря.
- Полный разбор фактов и тайминга — в [BATTLE.md](BATTLE.md).

## 5 золотых правил
1. Главное — **не лежать и не отдавать флаги** (красный SLA = минус очки).
2. **tcpdump с 10:00** — воруем чужие эксплойты из дампа.
3. **Бэкап всего ДО открытия сети** (железо, отката нет).
4. **Патч, не блокировка** (бан убьёт чекер).
5. **Всё говорим вслух**: нашёл баг / патчу X / ферма сдаёт.
