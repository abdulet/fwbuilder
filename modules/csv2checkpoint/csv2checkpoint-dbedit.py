#!/usr/bin/python
import re
import ipaddress as ip
import argparse

#Variables to access to the input (xml) and output (csv) files 
path = "."
dir_csv = "../../csv"
dir_cp = "cpscripts"

#Dictionary to store all url objects
urls = {}

#Dictionary to store all addresses objects
ipobjectsbyip = {}
#Dictionary to store not imported addresses because are dupplicated
duplicatedaddressbyname = {}

#Dictionary to store all elementes already added to any checkpoint script
#its mission is avoid duplicated objects
addedelements = {} 
logfile="csv2checkpoint.log"

#Options to automatize optimizations
avoidduplicatedobjects = False

parser = argparse.ArgumentParser()
parser.add_argument( "-p", "--policyname", dest="policyname", default="Standard", help="The name of the Checkpoint policy in which to import the rules", type=str  )
parser.add_argument( "-g", "--groupby", dest="groupby", default="auto", help="Which way to use for grouping rules [source|destination|service|raw|auto]", type=str  )
parser.add_argument( "-n", "--rulenumber", dest="rulenumber", default=0, help="The number of the las rule in the rulebase, the new rules will follow it", type=int  )
args = vars( parser.parse_args() )

def objectadded( name, objtype ):
    """
    Avoid duplicity of elements
    """

    objtype = objtype.lower()
    if objtype not in addedelements:
        addedelements[ objtype ] = []
    if name.lower() in addedelements[ objtype ]:
        print "Duplicated " + objtype.lower() + ": " + name
        return True
    else:
        addedelements[ objtype ].append( name.lower() )
        return False

def getcsvlines( fname ):
    f = open( path + "/" + dir_csv + "/" + fname, "r" )
    lines = []
    for line in f.readlines():
        lines.append( line.replace("\n", "") )
    f.close()

    return lines[1::]

def writecpscript( commands, filename ):
    f = open(path+"/"+dir_cp+"/"+filename, "w")
    for line in commands:
        f.write( unicode(line) + "\n" )
    f.close()

def swapname ( obj, objtype ):
    with open( path + "/cpservices.txt", "r" ) as f:
        cpservices = f.read().split( "\n" )
        upperservices = map( str.upper, cpservices )

    obj = obj.replace("/","_")
    replaced = obj

    if obj.find("-ALL") >= 0:
        replaced = obj.replace("-ALL", "-FULL")
    elif obj == "netbios-ssn":
        replaced = "NBT"
    elif obj.find("interface") >= 0:
        replaced = obj.replace("interface","int")
    elif obj.find("INTERFACE")  >= 0 :
        replaced = obj.replace("INTERFACE","INT")
    elif re.match( "^[0-9]", obj ) != None:
        replaced = "unicast-"+obj
    elif obj.upper() in upperservices:
        replaced = cpservices[ upperservices.index( obj.upper() ) ]

    if replaced != obj:
        print "INFORMATIONAL: Object name swapped: " + obj + " => " + replaced
        return replaced

    return obj

def importobjects():
    print "Importing network objects"

    lines=[]
    objgroups=[]
    objects = getcsvlines( "objects.csv" )
    for line in objects:
        fields = line.split( "," )
        objtype = fields[0]
        name = swapname( fields[1], "object" )
        addr = fields[2]

        if avoidduplicatedobjects == True:
            #Doesn't import objets with the same name or IP
            #than others already imported
            if not addr in ipobjectsbyip:
                #store address and name of first imported objects
                #used to substitute name of duplicated objects
                ipobjectsbyip[addr] = name
            else:
                #store the name and address of the duplicated objects
                #which are not imported
                duplicatedaddressbyname[ name ] = addr

            #check if object is already imported
            if objectadded ( addr, "address" ) or objectadded ( name, "object" ):
                continue

        description = fields[4]
        if objtype == "ip":
            netmask = fields[3]
            if netmask == "255.255.255.255":
                lines.append("create host_plain " + name )
            else:
                lines.append("create network " +  name)
                lines.append("modify network_objects " + name + " netmask " + netmask)

            lines.append("modify network_objects " + name + " ipaddr " + addr)
            lines.append("modify network_objects " + name + " comments \"" + description + "\"" )
        elif objtype == "group":
            objgroups.append( "create network_object_group " + name )
            for obj in addr.split( " " ):
                obj = obj.replace("/","_")
                obj = obj.replace("interface","int")
                if obj in urls:
                    obj = urls[ obj ]
                if re.match( "^[0-9]", obj ):
                    obj = "unicast-"+obj
                objgroups.append( "addelement network_objects " + name + " ''" + " network_objects:" + obj )
        elif objtype == "url":
            addr = "." + addr
            urls[ name ] =  addr
            lines.append ( "create domain " + addr )
            lines.append ( "modify network_objects " + addr + " comments " + description )
            
    lines.append ( "update_all" )
    objgroups.append ( "update_all" )
    writecpscript( lines + objgroups, "objects.cp.txt" )
    print " Network objects added: " + str( len( objects ) )

def importpools():
    print "Importing ip pools"
    lines=[]
    objects = getcsvlines( "pools.csv" )
    print "POOLS import not yet implemented!!!!"
    print " Add this pools manaully!!! "
    print "------------------------------------"
    print "\n".join( objects )
    print "------------------------------------"
    return
    for line in objects:
        fields = line.split( "," )
        name = fields[3]
        if objectadded ( name, "pool" ):
            continue
        firstaddr = fields[4]
        lastaddr = fields[5]
        lines.append( "create address_range " + name )
        lines.append( "modify network_objects " + name + " ipaddr_first " + firstaddr )
        lines.append( "modify network_objects " + name + " ipaddr_last " + lastaddr )
    lines.append("update_all")
    writecpscript( lines, "pools.cp.txt" )
    print " Pools added: " + str( len( objects ) )

def importusers():
    print "Importing users"
    lines = []
    passwords = []
    objects = getcsvlines( "users.csv" )
    for line in objects:
        fields = line.split( "," )
        name = fields[0]
        if objectadded ( name, "user" ):
            continue
        pwd = fields[1]
        lines.append( "create user " + name )
        lines.append( "modify users " + name + " auth_method 'Internal Password'" )
        passwords.append( "set_pass " + name + " '" + pwd + "'" )
    lines.append("update_all")
    lines = lines + passwords
    lines.append("update_all")
    writecpscript( lines, "users.cp.txt" )
    print " Users added: " + str( len( objects ) )

def importservices():
    print "Importing services"
    lines = []
    passwords = []
    objects = getcsvlines( "applications.csv" )
    f = open( "cpservices.txt", "r" )
    for line in f.readlines():
        cpservices = line.replace( "\n","" )
    f.close()
    for line in objects:
        print line
        name,proto,src,dst = line.split( "," )
        name = swapname( name, "service" )
        if objectadded ( name, "service" ) or name in cpservices:
            continue

        if src != "0-65535" and src != "1-65535":
            print " WARNING: source service not implemented yet"
            print " Add this service manually or implement me ;)"
            print " Service details: " + line
            continue

        if proto == "tcp":
            srvccmd = "create tcp_service"
        elif proto == "udp":
            srvccmd = "create udp_service"
        else:
            print " WARNING: Other protocol than tcp or udp, not implemented yet!"
            print " Add this service manually or implement me ;)"
            print "  Service details: " + line
            #srvccmd = "create other_service"
            continue
        lines.append( srvccmd + " " + name )
        lines.append( "modify services " + name + " port " + dst )
    lines.append("update_all")
    writecpscript( lines, "services.cp.txt" )
    print " Services added: " + str( len( objects ) )

def importservicegroups():
    print "Importing service groups"
    objects = getcsvlines( "application-groups.csv" )
    lines = []
    for line in objects:
        name,srvcs = line.split( "," )
        name = swapname( name, "service_group" )
        if objectadded ( name, "service_group" ):
            continue
        lines.append ( "create service_group " + name )
        for srvc in srvcs.split( " " ):
            lines.append ( "addelement services " + name + " '' services:" + srvc)
    lines.append("update_all")
    writecpscript( lines, "service-groups.cp.txt" )
    print " Service groups added: " + str( len( objects ) )

def atomizerules ( rules ):
    """
    Expand all rules so una line is for one source, one destination
    and one service.
    """

    atomized = []
    for rule in rules:
        name,action,log,source,destination,application,disabled = rule.split( "," )
        for src in source.split(" "):
            for dst in destination.split(" "):
                for app in application.split(" "):
                    atomized.append( name + "," + action + "," + log + "," + src + "," + dst + "," + app + "," + disabled )
    return atomized
        
def groupbydestination( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by destination
        key= ",".join([ destination, action, disabled, application ])
        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "sources" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not source in retrules[ key ][ "sources" ]:
            retrules[ key ][ "sources" ].append( source )
    return retrules

def groupbysource( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by source
        key= ",".join([ source, action, disabled, application ])
        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "destinations" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not destination in retrules[ key ][ "destinations" ]:
            retrules[ key ][ "destinations" ].append( destination )
    return retrules

def groupbyservice( rules ):
    retrules = {}
    for line in rules:
        #Loop each rule to find other ones to group with
        name,action,log,source,destination,application,disabled = line.split( "," )
        #Group rules by services
        key= ",".join([ application, action, disabled ])
        if not key in retrules:
            retrules[ key ] = {}
            retrules[ key ][ "destinations" ] = []
            retrules[ key ][ "sources" ] = []
        if not "log" in retrules[ key ] or ( "log" in retrules[ key ] and log == "Log" ):
            retrules[ key ][ "log" ] = log
        if not destination in retrules[ key ][ "destinations" ]:
            retrules[ key ][ "destinations" ].append( destination )
        if not source in retrules[ key ][ "sources" ]:
            retrules[ key ][ "sources" ].append( source )        
    return retrules

def optimizerules ( rules ):
    """
    Group rules that shares same source, destination, or action
    Three variants:
       1 "samedest": Same destination, service, action and status ( enabled or disabled)
       2 "samesrc" : Same source, service, action and status ( enabled or disabled)
       3 "samesrv" : Same service, action and status ( enabled or disabled)
    Then count wich variant have less rules and apply that to group the final rules
    """
    totalrules = len( rules )
    rules = atomizerules ( rules )
    grouped = {} # store grouped rules
    grouped [ "samedest" ] = groupbydestination( rules )
    grouped [ "samesrc" ] = groupbysource ( rules )
    grouped [ "samesrv" ] = groupbyservice ( rules )
    
    groupby = args[ "groupby" ]

    if groupby == "source":
        lessrules = "samesrc"
    elif groupby == "destination":
        lessrules =  "samedest"
    elif groupby == "service":
        lessrules = "samesrv"
    elif groupby == "auto":
        lessrules = sorted ( { "samedest": len( grouped [ "samedest" ] ), "samesrc": len( grouped [ "samesrc" ] ), "samesrv": len( grouped [ "samesrv" ] ) } )[ -1 ]

    retrules = []
    i=0
    for key, value in grouped[ lessrules ].items():
        #Build csv format again
        log = value[ "log" ]
        name = lessrules + str(i)
        if lessrules == "samedest":
            destination, action, disabled, application = key.split(",")
            source = " ".join( value["sources"] )
        elif lessrules == "samesrc":
            source, action, disabled, application = key.split(",")
            source = " ".join( value["destinations"] )
        elif lessrules == "samesrv":
            application, action, disabled = key.split(",")
            source = " ".join( value["sources"] )
            destination = " ".join( value["destinations"] )
        retrules.append( ",".join( [ name,action,log,source,destination,application,disabled ] ) )
        i+=1
    return retrules

def unhiderules ( rules ):
    #Ensure that no rule hides other one
    name,action,log,source,destination,application,disabled = line.split( "," )

def importpolicies():
    print "Importing access policies"
    lines=[]
    i=args[ "rulenumber" ]
    objects = getcsvlines( "policies.csv" )
    if args[ "groupby" ] != "raw":
        objects = optimizerules ( objects )
    #objects = unhiderules ( objects )
    for line in objects:
        name,action,log,source,destination,application,disabled = line.split( "," )
        if objectadded ( "From: " + source + " To: " + destination + " Service: " + application + " Action: " + action + " Disable: " + disabled, "policy" ):
            continue
        polname = args[ "policyname" ]
        lines.append( "addelement fw_policies ##" + polname + " rule security_rule" )
        lines.append( "modify fw_policies ##" + polname + " rule:" + str(i) + ":name " + name )
        lines.append( "modify fw_policies ##" + polname + " rule:" + str(i) + ":disabled " + disabled )
        lines.append( "rmbyindex fw_policies ##" + polname + " rule:" + str(i) + ":track 0" )
        lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":track tracks:" + log )
        lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":time globals:Any" )
        lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":install:'' globals:Any" )
        #lines.append( "rmbyindex fw_policies ##" + polname + " rule:" + str(i) + ":action 0" )
        if action == "accept":
            lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":action accept_action:" + action )
        elif action == "deny":
            lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":action drop_action:drop" )

        for src in source.split( " " ):
            if src in urls:
                src = urls[ src ]

            if avoidduplicatedobjects == True:
                #Looks if src is duplicated and, if is it, 
                #is substituted with the first imported one
                if src in duplicatedaddressbyname:
                    print "Changed source name %s for %s because it is the same IP" % ( src, ipobjectsbyip[duplicatedaddressbyname[ src ]] )
                    src = ipobjectsbyip[duplicatedaddressbyname[ src ]]

            if src.lower() == "any":
                src = "globals:Any"
            else:
                src = "network_objects:" + swapname( src, "object" )

            lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":src:'' " + src )
            lines.append( "modify fw_policies ##" + polname + " rule:" + str(i) + ":src:op ''" )

        for dst in destination.split( " " ):
            if dst in urls:
                print "url for dst: " + dst
                dst = urls[ dst ]
                print "url dst changed to: " + dst

            if avoidduplicatedobjects == True:
                #Looks if dst is duplicated and, if is it, 
                #is substituted with the first imported one
                if dst in duplicatedaddressbyname:
                    print "Changed destination name %s for %s because it is the same IP" % ( dst, ipobjectsbyip[duplicatedaddressbyname[ dst ]] )
                    dst = ipobjectsbyip[duplicatedaddressbyname[ dst ]]

            if dst == "any":
                dst = "globals:Any"
            else:
                dst = "network_objects:" + swapname( dst, "object" )

            lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":dst:'' " + dst )
            lines.append( "modify fw_policies ##" + polname + " rule:" + str(i) + ":dst:op ''" )
        
        for app in application.split( " " ):
            if app == "any":
                app = "globals:Any"
            else:
                app = "services:" + swapname( app, "service" )
            lines.append( "addelement fw_policies ##" + polname + " rule:" + str(i) + ":services:'' " + app )

        i += 1

    lines.append("update_all")
    writecpscript( lines, "policies.cp.txt" )
    print " Policies added: " + str( len( objects ) )

def importnat():
    print "NAT import not yet implemented!!!!"

importobjects()
#importpools()
#importusers()
#importservices()
#importservicegroups()
#importnat()
#importpolicies()

#orden dbedit: objects, services, service-groups, pools, policies, nat
