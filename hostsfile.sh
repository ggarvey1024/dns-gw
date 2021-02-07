#! /bin/sh
awk -- '(rtype == "A" && $1 ~ /\./)  || (rtype == "AAAA" && $1 ~ /:/)	\
	{for (i=2; i<=NF; i++) if (tolower($i) == tolower(host)) print $1}' \
	host="$1" rclass="$2" rtype="$3" /etc/hosts
