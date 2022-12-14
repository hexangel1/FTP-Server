# Simple FTP Server

## Поддерживамые команды

* ABOR, ALLO, APPE, CDUP, CWD
* DELE, EPSV, HELP, LIST, MDTM
* MKD,  NLST, NOOP, PASS, PASV
* PORT, PWD,  QUIT, REIN, RETR
* RMD,  RNFR, RNTO, SIZE, STAT
* STOR, STRU, SYST, TYPE, USER

## Установка и запуск

* Для сборки проекта перейдите директорию с проектом и
выполните команду `make`  
  `$ cd ftp && make`
* Для установки программы в систему перейдите директорию с проектом и
выполните команду `make install`  
  `$ cd ftp && make install`
* Для запуска ftp сервера выполните команду `./ftpserv`
передав ip адрес и порт в аргументах командной строки  
  `$ ./ftpserv -i 127.0.0.1 -p 2000`

## make команды

* `make ftpserv` - выполняет сборку проекта
* `make run` - выполняет сборку и осуществляет запуск проекта
* `make memcheck` - запускает проект с valgrind (проверка памяти)
* `make systrace` - запускает проект с strace (трассировка системных вызовов)
* `make stop` - останавливает запущенный проект
* `make tags` - генерирует tags файлы для работы в vim
* `make tar` - создает tar архив с файлами проекта
* `make clean` - выполняет очистку от мусорных файлов
* `make install` - осуществляет установку программы в системy
* `make uninstall` - удаляет установленную программу из системы

