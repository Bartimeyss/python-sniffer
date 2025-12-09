# Sniffer

Простой сниффер на RAW-сокетах (Linux) с сохранением в pcap и генерацией отчёта по IP/направлениям/времени.

## Установка

Python 3.x, зависимости стандартной библиотеки. Дополнительно ничего ставить не нужно.

## Использование

Сниффер (требуются права на RAW-сокеты):
```
python main.py sniff -i eth0 -i wlan0 -o capture.pcap
```

Отчёт по pcap:
```
python main.py report capture.pcap -b 120
```

## Тесты

```
python -m unittest discover -s tests
```
