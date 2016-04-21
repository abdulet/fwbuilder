#!/usr/bin/env python
import preprocessing

#Address of the Security Management Server
SMSip=1.1.1.1
SMSuser="admin"
SMSpwd="pass"

#Variables to access to the input (xml) and output (csv) files 
path = "."
dir_csv = "../../csv"
dir_cp = "cpscripts"

#File to log operations
logfile="csv2checkpoint.log"

#Options to automate optimizations
avoidduplicatedobjects = False #Search for duplicated objects with same ip or name
groupby="raw" #Which way to use for grouping rules [source|destination|service|raw|auto]
rulenumber=0 #The number of the las rule in the rulebase, the new rules will follow it
rulenamenumber=0 #The start number that will be concatenate to the rulename, when groupby is not raw

#The name of the Checkpoint policy in which to import the rules
policyname="Standard"
