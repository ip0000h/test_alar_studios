# alar-studios-testing

## Запуск через docker-compose

`docker-compose up`

## Описание

Сервис будет доступен по <http://localhost:5000>

### Первая часть

Первая часть - все должно быть понятно, пользователи редактируются, добавляются и удаляются.

Для тестов в бд сразу создаются 2 пользователя admin и regular c такими же паролями.

Из того что не успел сделать:

1)надо было все методы по работе с пользователями вывести в class based view для наглядности

2)я обновляю страницу полностью после создания пользователя, хотя возможно было добавить строку в таблицу после запроса

3)нужно было деактивировать кнопку save до изменений в строке

### Вторая часть

Создал еще один сервис, который просто раздает json файлы

Результат задания будет доступен по <http://localhost:5000/json_async>

### Потраченое время

~12 часов
