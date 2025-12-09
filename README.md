# Sniffer

Простой сниффер на RAW-сокета на линукс с сохранением в pcap и генерацией отчёта ip, хостам, времени, объёму трафика..


## Использование

Сниффер (требуются права на RAW-сокеты):
```
python main.py sniff -i eth0 -i wlan0 -o capture.pcap
```

Отчёт по pcap:
```
python main.py report capture.pcap -b 120
```


