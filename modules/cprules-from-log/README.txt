Introuctions of use:
    1-copy logexport.ini to the log server $FWDIR/conf
    2-SSH to the log server and run
        fwm logexport -d, -n -p | cut -d\, -f 2,3,4,6,7,8 | sort | uniq > rules.csv
    3-Copy the file rules.csv to your machine
    4-Run ./data-from-log.py
