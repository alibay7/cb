#!/bin/bash

function usage() {								# Function: Exit with error.
  echo usage: $0 -u CBR Server URL -t API Token >&2
}

exit_abnormal() {								# Function: Exit with error.
  usage
  exit 1
}


while getopts ":u:t:" option;
do
 case "${option}" in
	u) url=${OPTARG};;
	t) token=${OPTARG};;
	:) 										  # If expected argument omitted:
		echo "Error: -${OPTARG} requires an argument."
		exit_abnormal                            
		;;
	*)                                         # If unknown (any other) option:
		exit_abnormal                            
		;; 
 esac
done


shift $((OPTIND-1))
if [ -z "${url}" ] || [ -z "${token}" ]
	then
		exit_abnormal
	fi

function banner(){

cat << "EOF"
   _____           _                 ____  _            _      _____                                      
  / ____|         | |               |  _ \| |          | |    |  __ \                                     
 | |     __ _ _ __| |__   ___  _ __ | |_) | | __ _  ___| | __ | |__) |___  ___ _ __   ___  _ __  ___  ___ 
 | |    / _` | '__| '_ \ / _ \| '_ \|  _ <| |/ _` |/ __| |/ / |  _  // _ \/ __| '_ \ / _ \| '_ \/ __|/ _ \
 | |___| (_| | |  | |_) | (_) | | | | |_) | | (_| | (__|   <  | | \ \  __/\__ \ |_) | (_) | | | \__ \  __/
  \_____\__,_|_|  |_.__/ \___/|_| |_|____/|_|\__,_|\___|_|\_\ |_|  \_\___||___/ .__/ \___/|_| |_|___/\___|
                                                                              | |                         
                                                                              |_|                         
EOF

}

function main() {
	banner

	curl https://attack.mitre.org/ >mitre.txt 2>&1
	mitre=$(grep -io "t[0-9][0-9][0-9][0-9]" mitre.txt  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq |wc -l)  # Total Number of MITRE ATT&CK Techniques


	curl -XGET -H "X-Auth-Token: $token" -H "Content-Type: application/json" "$url/api/v1/threat_report?cb.urlver=1&cb.fq.feed_name=attackframework&cb.fq.feed_name=bit9advancedthreats&cb.fq.feed_name=cbcommunity&cb.fq.feed_name=sans&cb.fq.feed_name=bit9endpointvisibility&cb.fq.feed_name=bit9suspiciousindicators&cb.fq.feed_name=bit9earlyaccess&sort=severity_score%20desc&rows=50000&facet=false&start=0&cb.fq.is_deleted=false" -k > out.txt 2>&1
	RESULT=$(grep -io "t[0-9][0-9][0-9][0-9]" out.txt  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq | wc -l)
	
	rm -rf out.txt				# Delete Output File
	rm -rf mitre.txt			# Delete Output File

	echo "###########################################################################################################"
	echo "############       $RESULT out of $mitre MITRE ATT&CK Techniques Covered by CarbonBlack Response      ############"
	echo "###########################################################################################################"
}

main
