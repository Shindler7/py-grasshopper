# Учебный Python/Rust проект по шифрованию данных

- **Python** — "обёртка" для взаимодействия с rust-приложением по шифрованию
  данных;
- **Rust** — учебная библиотека блочного
  шифрования [block-encryption](https://gitverse.ru/digit4lsh4d0w/block-encryption).
  В частности используется шифр "Кузнечик" (ГОСТ 34.12-2018).

**Важно**: это учебный проект, использование которого возможно только **в
личных и учебных целях**. Его нельзя применять для задач, которые в
соответствии с законодательством Российской Федерации подлежат лицензированию.

## Инсталляция

### Для опытных

Для компиляции Rust-пакетов
требуется [установка Rust](https://www.rust-lang.org/tools/install), и,
возможно, [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

Далее механизм прост.

```shell
(.venv) pip install git+https://github.com/Shindler7/py-grasshopper.git
(.venv) maturin develop --uv
```

### Для ленивых

Установить актуальную версию из [GitHub Release](https://github.com/Shindler7/py-grasshopper/releases/download/v0.3.0/py_grasshopper-0.3.0-cp313-cp313-win_amd64.whl):
```shell
(.venv) pip install https://github.com/Shindler7/py-grasshopper/releases/download/v0.3.0/py_grasshopper-0.3.0-cp313-cp313-win_amd64.whl
```

## Использование

```pycon
>>> from grass_crypt.interfaces import encrypt, decrypt
>>>
>>> code = 'pass12345'
>>> text = 'text text text text'
>>> 
>>> e = encrypt(text, code=code)
>>> print(e)
b'A7wfJmUk/7RcZQyG4U76sQy7mI3tQoanu73R5126M(...)'
>>>
>>> d = decrypt(e, code=code)
'text text text text'
```

**Дополнительный функционал:**

Для работы с файлами доступны методы: ``interfaces.encrypt_file`` и
``intefaces.decrypt_file``.

**Важно**: записываются зашифрованные файлы всегда в бинарном режиме и также
считываются. При шифровании делается попытка определить тип файла (str, bytes),
и если успешно, данные о типе данных сохраняются в метастроке. При удачной
дешифровке сохраняется файл с первоначальным типом.

## Режимы шифрования

*С версии 0.3.0*

Аттрибут ``mode`` может принимать все значения, предоставленные
``EncryptMode``. При дешифровке использованный метод извлекается из метастроки.

Подробности о методах шифрования в репозитории автора алгоритма.

## История версий

- 0.3.0 — оптимизирован код, улучшена работа шифрования и дешифрования файлов,
  внедрено и проведено тестирование, структурирован код в Rust, добавлена
  обработка всех доступных методов шифрования, а также внедрена сквозная
  обработка исключений.
- 0.2.0 — улучшена логика работы функций ``encrypt`` и ``decrypt``. Добавлены и
  проведены автотесты.
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