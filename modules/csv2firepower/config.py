#!/usr/bin/env python

#CSV header to search for in every csv file
#to ensure the format is addecuate to the module
csv_header="##%%FIREPOWER%%##"

#Address of the Firepower Management Console 
FMCip="10.207.31.27"
FMCuser="apiuser"
FMCpwd="m@c@ncet"

#Variables to input and output files
path = "." #root dir for other paths
dir_csv = "csv/" #Path which stores the input csv files

#Path of the libs dir
libdir = "libs/"

#File to log operations
logfile="csv2firepower.log"

#Options to automate optimizations
avoidduplicatedobjects = False #Search for duplicated objects with same ip or name
groupby="raw" #Which way to use for grouping rules [source|destination|service|raw|auto]
rulenumber=0 #The number of the las rule in the rulebase, the new rules will follow it
rulenamenumber=0 #The start number that will be concatenate to the rulename, when groupby is not raw

#The name of the Checkpoint policy in which to import the rules
policyname="ACESA-ACL"
