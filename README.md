# scoring-api
Реализовал декларативный язык описания и систему валидации запросов к HTTP API сервиса скоринга.

### Конфигурирование

Конфигурирование реализовано через параметры командной строки.
```
--log - путь до лог файла
--port - порт для приема HTTP запросов
```
По умолчанию порт  8080, а лог пишется в stdout.

## Запуск

python3 api.py

