# Учебный Python/Rust проект по шифрованию данных

## <span style="color:red">ПРЕДВАРИТЕЛЬНЫЙ КОММИТ. НЕФУКЦИОНАЛЬНО.</span>

- **Python** — "обёртка" для взаимодействия с rust-приложением по шифрованию
  данных;
- **Rust** — шифровальщик, использующий алгоритм "Кузнечик" (ГОСТ 34.12-2018).
  Репозиторий приложения
  на [gitverse](https://gitverse.ru/digit4lsh4d0w/cryptography/content/main).

**Важно**: это учебный проект, использование которого возможно только **в
личных и учебных целях**. Его нельзя применять для задач, которые в
соответствии с законодательством Российской Федерации подлежат лицензированию.

## Инсталляция

Для компиляции Rust-пакетов
требуется [установка Rust](https://www.rust-lang.org/tools/install), и,
возможно, потребуется
установить [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

Далее механизм прост.

```shell
(.venv) pip install git+https://github.com/Shindler7/py-grasshopper.git
(.venv) maturin build 
```

## Использование

```python
from grass_crypt.interfaces import do_encrypt


def encrypt():
    result = do_encrypt('string for encrypt', key='pass1234')
    print(result)
```

## История версий

- 0.1.0 — базовый функционал взаимодействия.

## Использованные технологии

- [PyO3](https://github.com/PyO3/pyo3)

## Лицензия

[MIT License](https://opensource.org/license/mit)

Copyright 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.