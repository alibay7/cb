#!/bin/bash

function banner()                               # Function: Banner.
{

    cat << "EOF"

    ____  ___________________   _______ ___________   __
   / __ \/ ____/ ____/ ____/ | / / ___// ____/  _/ | / /
  / / / / __/ / /_  / __/ /  |/ /\__ \/ __/  / //  |/ /
 / /_/ / /___/ __/ / /___/ /|  /___/ / /____/ // /|  /
/_____/_____/_/   /_____/_/ |_//____/_____/___/_/ |_/



EOF

}


function usage()                                # Function: Exit with error.
{
  echo usage: $0 -u CBR Server URL -t API Token >&2
  exit 1

}


while getopts ":u:t:" option;
do
 case "${option}" in
    u) url=${OPTARG};;
    t) token=${OPTARG};;
    :)                                        # If expected argument omitted:
        echo "Error: -${OPTARG} requires an argument."
        usage
        ;;
    *)                                         # If unknown (any other) option:
        usage
        ;;
 esac
done


shift $((OPTIND-1))
if [ -z "${url}" ] || [ -z "${token}" ]
    then
        usage
    fi

function JSON()                                # Function: Save MITRE Navigator compatible JSON file.
{
    echo '{
        "description": "",
        "domain": "mitre-enterprise",
        "filters": {
            "platforms": [
                "windows"
            ],
            "stages": [
                "act"
            ]
        },
        "gradient": {
            "colors": [
                "#ff6666",
                "#ffe766",
                "#8ec843"
            ],
            "maxValue": 100,
            "minValue": 0
        },
        "hideDisabled": false,
        "legendItems": [],
        "name": "Cb Response - Windows",
        "selectTechniquesAcrossTactics": true,
        "showTacticRowBackground": false,
        "sorting": 0,
        "tacticRowBackground": "#dddddd",
        "techniques": [' >CbResponseNavigator.json


    while IFS= read -r line
    do
        echo "  {
             \"color\": \"#00ff61\",
         \"techniqueID\": \"$line\"
        },"
    done <totalattack.json >>CbResponseNavigator.json

    sed -i '$ s/.$//' CbResponseNavigator.json

    echo '],
        "version": "2.1",
        "viewMode": 0
    }'>>CbResponseNavigator.json

    echo
    echo "[!]Saved MITRE Navigator json file as CbResponseNavigator.json"
    echo "[!]Use this file to 'Open Existing Layer' from local file on https://mitre.github.io/attack-navigator/enterprise/"

}



function main()                                 # Main Function: Gather the covarege from CB threat feeds.
{
	banner

    # Total Number of MITRE ATT&CK Techniques
	curl https://attack.mitre.org/ >mitre.json 2>&1
	mitre=$(grep -io "t[0-9][0-9][0-9][0-9]" mitre.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq |wc -l)
	grep -io "t[0-9][0-9][0-9][0-9]" mitre.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq >mitreattack.json

    # Total Number of TI Feed Techniques
	curl -XGET -H "X-Auth-Token: $token" -H "Content-Type: application/json" "$url/api/v1/threat_report?cb.urlver=1&cb.fq.feed_name=attackframework&cb.fq.feed_name=bit9advancedthreats&cb.fq.feed_name=cbcommunity&cb.fq.feed_name=sans&cb.fq.feed_name=bit9endpointvisibility&cb.fq.feed_name=bit9suspiciousindicators&cb.fq.feed_name=bit9earlyaccess&sort=severity_score%20desc&rows=50000&facet=false&start=0&cb.fq.is_deleted=false" -k > feed.json 2>&1
	resultfeed=$(grep -io "t[0-9][0-9][0-9][0-9]" feed.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq | wc -l)
    grep -io "t[0-9][0-9][0-9][0-9]" feed.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq >feedattack.json

    # Total Number of Watchlist Techniques
    curl -XGET -H "X-Auth-Token: $token" -H "Content-Type: application/json" "$url/api/v1/watchlist" -k > watchlist.json 2>&1
    resultwatchlist=$(grep -io "t[0-9][0-9][0-9][0-9]" watchlist.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq | wc -l)
    grep -io "t[0-9][0-9][0-9][0-9]" watchlist.json  |sed -e 's/^\(.\)/\U\1/g' |sort | uniq >watchlistattack.json



    cat watchlistattack.json  feedattack.json |sort | uniq >> totalattack.json
	totalresult=$(cat totalattack.json|sort | uniq | wc -l)

	echo "[!] $totalresult ($resultwatchlist from Watchlists, $resultfeed from CB Threat Intel Feeds ) out of $mitre MITRE ATT&CK Techniques Covered by CarbonBlack Response"
	echo
	echo "[!]Following MITRE ATT&CK Techniques Covered "
	cat totalattack.json |paste -s -d, -
	echo
	echo "[!]Following MITRE ATT&CK Techniques Not Covered"
	comm -13 totalattack.json mitreattack.json |paste -s -d, -
}

main
JSON

rm -rf watchlist.json  mitreattack.json watchlistattack.json feedattack.json feed.json  mitre.json totalattack.json # Delete Output File
