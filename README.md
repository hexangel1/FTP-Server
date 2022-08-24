# Simple FTP Server

## Поддерживамые команды

* ABOR, CDUP, CWD,  DELE, HELP
* LIST, MDTM, MKD,  NLST, NOOP
* PASS, PASV, PORT, PWD,  QUIT
* REIN, RETR, RMD,  SIZE, STOR
* SYST, TYPE, USER

## Установка и запуск

* Для сборки проекта перейдите директорию с проектом и
выполните команду `make`  
  `$ cd ftp && make`
* Для запуска ftp сервера выполните команду `./ftpd` передав ip адрес и порт
в аргументах командной строки  
  `$ ./ftpd 127.0.0.1 2000`

## make команды

* `make ftpd` - выполняет сборку проекта
* `make run` - выполняет сборку и осуществляет запуск проекта
* `make stop` - останавливает запущенный проект
* `make memcheck` - запускает проект с valgrind (проверка памяти)
* `make systrace` - запускает проект с strace (трассировка системных вызовов)
* `make tags` - генерирует tags файлы для работы в vim
* `make tar` - создает tar архив с файлами проекта
* `make clean` - выполняет очистку от мусорных файлов

