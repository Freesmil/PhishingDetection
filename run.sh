#!/bin/bash
while IFS='' read -r line || [[ -n "$line" ]]; do
	wget -qO- -t 1 --connect-timeout=5 $line > /home/hagrid/Dokumenty/Bachelor/output1.txt
	google-chrome-stable --headless --timeout=5000 --virtual-time-budget=5000 --disable-gpu --dump-dom http://$line > /home/hagrid/Dokumenty/Bachelor/output2.txt

	python3.5 /home/hagrid/PycharmProjects/phishing_detection/main.py /home/hagrid/Dokumenty/Bachelor/output1.txt /home/hagrid/Dokumenty/Bachelor/output2.txt $line
	
	rm /home/hagrid/Dokumenty/Bachelor/output1.txt
	rm /home/hagrid/Dokumenty/Bachelor/output2.txt

done < "$1"
