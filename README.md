# Certipy - AD CS Attack & Enumeration Toolkit

[![PyPI version](https://img.shields.io/pypi/v/certipy-ad?v5.0.3)](https://pypi.org/project/certipy-ad/)
![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![License](https://img.shields.io/github/license/ly4k/Certipy)

**Certipy** is a powerful offensive and defensive toolkit for enumerating and abusing Active Directory Certificate Services (AD CS). It helps red teamers, penetration testers, and defenders assess AD CS misconfigurations - including full support for identifying and exploiting all known **ESC1-ESC17** attack paths.

> [!WARNING]
> Use only in environments where you have explicit authorization. Unauthorized use may be illegal.

---

## 🔍 Features

* 🔎 Discover Certificate Authorities and Templates
* 🚩 Identify misconfigurations
* 🔐 Request and forge certificates
* 🎭 Perform authentication using certificates
* 📡 Relay NTLM authentication to AD CS HTTP(S)/RPC endpoints
* 🗝️ Support for Shadow Credentials, Golden Certificates, and Certificate Mapping Attacks
* 🧰 And much more!

---

## 📚 Full Wiki & Documentation

Read the full **step-by-step usage guide**, including installation, vulnerability explanations, examples, and mitigations in the [📘 Certipy Wiki](https://github.com/ly4k/Certipy/wiki).

---

## ⚙️ Installation

See the [Installation Guide](https://github.com/ly4k/Certipy/wiki/04-%E2%80%90-Installation) for instructions on how to install Certipy.

---

## 🇷🇺 Поддержка кириллицы

Это форк [ly4k/Certipy](https://github.com/ly4k/Certipy) с исправлениями для
доменов, имена в которых не помещаются в latin-1 — `Пётр@КОРПОРАЦИЯ.РФ` и
подобные. Больше ничего не изменено, весь набор команд upstream работает так же.

### Почему форк, а не правка site-packages

Обычный совет — выправить установленные копии `pyasn1`, `six`, `asn1crypto` и
`impacket` прямо в `site-packages`. Так делать не надо: правки теряются при
любой переустановке зависимостей — `uv sync`, `pip install -U`, или обычный
`pip install`, решивший, что версия изменилась. Отказ выглядит неприятно:
инструмент работает, а потом после «просто обновления» на другой машине
молча перестаёт.

Здесь исправления живут в коде самого Certipy и включаются при импорте, поэтому
переживают обновление зависимостей.

### Что на самом деле требовало исправления

Три независимых бага, все закрыты тестами в `tests/test_cyrillic.py`:

| Где | В чём дело |
|---|---|
| `impacket.structure.Structure.ENCODING` | Жёстко зашит `latin-1`; любое имя вне latin-1 даёт `UnicodeEncodeError` при сериализации ccache. |
| `six.b()` | Тоже жёстко `latin-1`; `impacket.krb5.ccache` вызывает его в `Principal.prettyPrint()`. |
| `impacket.krb5.ccache.Principal.fromPrincipal` | Клал `len(str)` — **число символов** — в поле, где должно быть **число байт**. Вот это неприятный случай: файл писался **без ошибки**, но слишком короткий, и при чтении возвращался мусор. Именно поэтому `certipy auth` рапортовал «Wrote credential cache to …», а `unpac` файл потом не мог использовать. |

Две вещи, которые обычно правят, здесь намеренно **не** тронуты:

- **`pyasn1`** — не нужен. `impacket.krb5.asn1.KerberosString` уже выставляет
  `encoding = 'utf-8'` в upstream начиная с impacket 0.13. Правка
  `pyasn1.type.char` меняла бы `GeneralString` для всех прочих библиотек в
  процессе.
- **`asn1crypto`** — глобально не правится: `_encoding = 'latin1'` там это ровно
  то, что предписывает X.680 для `NumericString` / `PrintableString` /
  `VisibleString`. Ошибка была в самом Certipy: керберосовские строки были
  объявлены как `core.GeneralString` в `certipy/lib/structs.py`. Теперь это
  подкласс `KerberosString`, переопределяющий только кодек.

### Установка

**Вариант A — venv через uv** (рекомендуется). `uv venv` создаёт окружение
**без pip**, поэтому для варианта с pip нужен флаг `--seed`.

```bash
# uv
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install "certipy-ad @ git+https://github.com/akhomlyuk/Certipy.git"
```

```bash
# pip — обязательно --seed, иначе pip в venv не будет
uv venv --python 3.12 --seed .venv
source .venv/bin/activate
pip install "certipy-ad @ git+https://github.com/akhomlyuk/Certipy.git"
```

Активация нужна, чтобы `certipy` и `python` указывали на venv, а не на системные.
Без активации можно ставить по пути, но `certipy` в PATH не попадёт:

```bash
uv pip install --python .venv/bin/python "certipy-ad @ git+https://github.com/akhomlyuk/Certipy.git"
.venv/bin/certipy req ...
```

**Вариант B — `uv tool install`.** Это **не venv**. uv создаёт отдельное
окружение в `~/.local/share/uv/tools/certipy-ad` и кладёт бинарник в
`~/.local/bin`. Системные пакеты при этом не страдают, но:

- окружение нельзя активировать, туда нельзя доустановить пакеты обычным `pip`;
- оно общее для всей машины, не per-project;
- обновляется только через `uv tool upgrade`.

Для разового использования CLI это удобно, для курса — нет: нельзя положить
рядом другие инструменты в то же окружение.

```bash
uv tool install "certipy-ad @ git+https://github.com/akhomlyuk/Certipy.git"
```

**Вариант C — в проекте с lock-файлом.** Пинытся версия, `uv sync` поднимает
то же окружение у всей группы.

```bash
uv add "certipy-ad @ git+https://github.com/akhomlyuk/Certipy.git"
uv sync
uv run certipy req ...
```

Нужны Python 3.12+ и impacket >= 0.13.

### Проверить, что всё встало в venv, а не глобально

```bash
python -c "import certipy, sys; print(certipy.__file__)"
```

Путь обязан начинаться с пути вашего venv (`.../.venv/...`). Если видите
`/usr/lib/python3/...` — стоит глобально, и нужно разбираться с тем, как ставили.

### Проверка

```bash
certipy req -u 'Пётр' -p 'password' -target dc.corp.example -ca 'CA' -template 'User' -upn 'Пётр@КОРПОРАЦИЯ.РФ'
certipy auth -username 'Пётр' -password 'password' -dc-ip 10.0.0.5 -domain corp.example
certipy unpac -outfile 'Пётр.pac'
```

Вторая команда создаёт `Пётр.ccache`; его можно передать обратно через
`-k ./Пётр.ccache`.

### Как отключить

```bash
CERTIPY_NO_CYRILLIC=1 certipy req ...
```

Возвращает штатное поведение latin-1. Нужно только если хочется сравнить вывод с
upstream.

---

## 🚀 Quick Start

See the [Quick Start Guide](https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage) for a quick overview of the most common commands and usage examples.

---

## 🎯 Supported AD CS Vulnerabilities

Certipy supports detection and exploitation of AD CS vulnerabilities across the full range of ESC1-ESC17.

For detailed explanations and exploitation steps, refer to the [Certipy Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation).

---

## 📎 Resources

See the [Resources](https://github.com/ly4k/Certipy/wiki/03-%E2%80%90-Resources) for selection of key resources related to AD CS security.

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, improving documentation, or submitting pull requests.

---

## 🌟 Sponsors

Thanks to these generous sponsors for supporting the development of this project. Your contributions help sustain ongoing work and improvements.

<!-- sponsors --><a href="https://github.com/mxrch"><img src="https:&#x2F;&#x2F;github.com&#x2F;mxrch.png" width="60px" alt="User avatar: mxrch" /></a><!-- sponsors -->

---

## 👤 Author

Developed by [@ly4k](https://github.com/ly4k), with valuable contributions from the community.

---

## 📘 Wiki

📖 Visit the [**Certipy Wiki**](https://github.com/ly4k/Certipy/wiki) for detailed documentation, usage examples, ESC vulnerability breakdowns, and mitigation advice.
