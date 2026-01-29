#!/bin/bash

INDEXES=(windows linux network web mail security sql fail2ban)

for index in "${INDEXES[@]}"; do
	sudo /opt/splunk/bin/splunk add index "$index"
done