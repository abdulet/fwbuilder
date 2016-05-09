#!/usr/bin/python
import sys
import ipaddress
import config as cfg
sys.path.insert( 0, cfg.libdir )
from expect import run_commands
import cpgetdata

internal_nets = { "10.100.25.0":"255.255.255.0", "10.1.11.0":"255.255.255.0", "172.26.0.0":"255.255.0.0", "192.168.125.0":"255.255.255.0", "192.168.240.0":"255.255.255.0", "192.168.25.0":"255.255.255.0", "192.168.252.0":"255.255.255.0", "192.168.254.0":"255.255.255.0", "192.168.255.0":"255.255.255.0", "192.168.30.0":"255.255.255.0", "192.168.75.0":"255.255.255.0" }

outputpath = "./output/"
filerules = "policies.csv"
fileapplications = "applications.csv"
fileobjects = "objects.csv"

inrules = []
outrules = []
applications = []
objects = []
cpservices = {}

historicpolicies = []
historicobjects = []
historicapplications = []

def loadhistoric ():
    for fname in [ filerules, fileobjects, fileapplications ]:
        f = open( outputpath + "historic-" + fname, "r" )
        i=0
        for line in f.readlines():
            if i == 0:
                i = 1
                #avoid to load the csv header
                continue
            if fname == filerules:
                historicpolicies.append( unicode( line.replace("\n", "") ) )
            elif fname == fileobjects:
                historicobjects.append( unicode( line.replace("\n", "") ) )
            else:
                historicapplications.append( unicode( line.replace("\n", "") ) )
        f.close()

def isdefined( obj, objtype ):
    #obj is a list, objtype a string
    if objtype == "policy":
        if not ",".join( obj[1:6] ) in historicpolicies:
            historicpolicies.append( ",".join( obj[1:6] ) )
            return False

    elif objtype == "object":
        if not ",".join( obj ) in historicobjects:
            historicobjects.append( ",".join( obj ) )
            return False

    elif objtype == "application":
        if not ",".join( obj ) in historicapplications:
            historicapplications.append( ",".join( obj ) )
            return False

    return True

def writecsv( filename, header, lines ):
    f = open( outputpath + filename, "w" )
    f.write( unicode( header + "\n" ) )
    for line in lines:
        f.write( unicode( line + "\n" ) )
    f.close()

def getcpservices ():
    f = open("cpservices.csv", "r")
    i=0
    cpservices["other_service"] = []
    cpservices["service_group"] = {}
    for line in f.readlines():
        if i==0:
            i+=1
            continue
        if len( line.split(",") ) == 4:
            name,proto,port,srcport = line.split(",")
            srcport = srcport.replace("\n","")
            cpservices[port+"/"+proto] = { "name":name, "srcport":srcport }
        elif len( line.split(",") ) == 2 :
            name,other = line.split(",")
            other = other.replace("\n","")
            if other == "other_service":
                cpservices["other_service"].append( name )

def getobjecttype ( obj ):
    if obj in internal_nets:
        return "net"
    else:
        return "host"

#def addrinnets( addr, net ):

def getspecialapplication( proto, port ):
    if proto == "icmp":
        return "icmp-proto"
    
    return False
    
def getconnections( logfile=None ):
    try:
        f = open( logfile, "r" )
        lines = f.readlines()
        f.close()
    except:
        run_commands( smsip, smsuser, smspwd, [ "echo \"[Fields_Info]\nincluded_fields=num,rule_name,src,dst,s_port,service,proto,action\" > ~/logexport.ini", "fwm logexport -n -p" ], 22, "ssh" )
    i=0
    action="accept"
    log="Log"
    disabled="true"
    rules = { "incoming": {}, "outgoing":{} }
    objects2add = {}
    for line in lines:
        i+=1
        fields = line.split( "," )
        source = fields[2]
        destination = fields[3]
        srcport = fields[4]
        port = fields[5] 
        proto = fields[6]
        application = False
        
        direction = "incoming"
        try:
            srcip = ipaddress.ip_address( unicode( source ) )
            if srcip.is_private:
                #Is an outgoing connection
                direction = "outgoing"
            else:
                for net in internal_nets:
                    if srcip in ipaddress.ip_network( unicode( net + "/" + internal_nets[net] )):
                    #Check if source is part of an internal net
                        direction = "outgoing"
            #Check if destination is a valid IP
            ipaddress.ip_address( unicode( destination ) )
        except ValueError:
            #Invalid source or destination IP
            print "Invalid source or destination IP"
            print "source: " + source
            print "destination: " + destination
            print line
            continue
        except Exception as error:
            raise error

        if getobjecttype( source ) == "net":
            srcobj = [ "ip", "impred_"+source, source, internal_nets[ source ], "" ]
            source = "impred_"+source
        else:
            srcobj = [ "ip", "imphost_"+source, source, "255.255.255.255", "" ]
            source = "imphost_"+source
        objects2add[ source ] = srcobj

        #if not isdefined( srcobj, "object" ):
        #        objects.append( ",".join( srcobj ) )

        if getobjecttype( destination ) == "net":
            dstobj = [ "ip", "impred_"+destination, destination, internal_nets[ destination ], "" ]
            destination = "impred_"+destination
        else:
            dstobj = [ "ip", "imphost_"+destination, destination, "255.255.255.255", "" ]
            destination = "imphost_"+destination
        objects2add[ destination ] = dstobj

        #if not isdefined( dstobj, "object" ):
        #    objects.append( ",".join( dstobj ) )

        #Check if application is a service defined in checkpoint
        if port+"/"+proto in cpservices:
            if cpservices[ port+"/"+proto ]["srcport"] == "":
                #There is no src port so the service is defined in CP
                application = cpservices[ port+"/"+proto ]["name"]
            elif cpservices[ port+"/"+proto ]["srcport"] == srcport:
                #There is srcport and is the same as the rule
                #so the service is defined in CP
                application = cpservices[ port+"/"+proto ]["name"]
        else:
            application = getspecialapplication( proto, port )

        if not application and direction == "incoming":
            #Skip non standard applications
            print "Non standard application in rule"
            print line
            continue
            #if not isdefined( [ proto + "_" + port, proto, "1-65535", port ], "application" ) :
                #The service is not defined in CP, we should add it
            #    applications.append( ",".join( [ "imp_" + proto + "_" + port, proto, "1-65535", port ] ) )
            #application = "imp_" + proto + "_" + port

        
        if direction == "outgoing":
            if not source in rules[ direction ]:
                rules[ direction ] [ source ] = {}
            if not application in rules[ direction ][ source ]:
                rules[ direction ][ source ][ application ] = {"port": port, "proto": proto, "destinations": []}
            if not destination in rules[ direction ][ source ][ application ]:
                rules[ direction ][ source ][ application ][ "destinations" ].append( destination )
        elif direction == "incoming":
            if not destination in rules[direction]:
                rules[ direction ][ destination ] = {}
            if not application in rules[ direction ][ destination ]:
                rules[ direction ][ destination ][ application ] = {"port": port, "proto": proto, "sources": []}
            if not source in rules[ direction ][ destination ][ application ]:
                rules[ direction ][ destination ][ application ][ "sources" ].append( source )

    i=0
    direction = "incoming"
    if len( rules[direction] ) > 0:
        for destination in rules[ direction ]:
            if len( rules[ direction ][ destination ] ) > 0:
                for application in rules[ direction ][ destination ]:
                    if len( rules[ direction ][ destination ][ application ][ "sources" ] ) > 0:
                        #if len( rules[ direction ][ destination ][ application ][ "sources" ] ) > 10:
                        #    source = "any"
                        #else:
                        source = " ".join( rules[ direction ][ destination ][ application ][ "sources" ] )
                        
                        port = rules[ direction ][ destination ][ application ][ "port" ]
                        proto = rules[ direction ][ destination ][ application ][ "proto" ]

                        app = False
                        if port+"/"+proto in cpservices:
                            if cpservices[ port+"/"+proto ]["srcport"] == "":
                                #There is no src port so the service is defined in CP
                                app = cpservices[ port+"/"+proto ]["name"]
                            elif cpservices[ port+"/"+proto ]["srcport"] == srcport:
                                #There is srcport and is the same as the rule
                                #so the service is defined in CP
                                app = cpservices[ port+"/"+proto ]["name"]
                        else:
                            app = getspecialapplication( proto, port )

                        if not app:
                            if not isdefined( [ proto + "_" + port, proto, "1-65535", port ], "application" ) :
                                #The service is not defined in CP, we should add it
                                applications.append( ",".join( [ "imp_" + proto + "_" + port, proto, "1-65535", port ] ) )
                            app = "imp_" + proto + "_" + port

                        #if len ( rules[ direction ][ destination ] ) > 10:
                        #    app = "any"
                        name = direction + str(i)
                        rule = [ name,action,log,source,destination,app,disabled ]

                        if not isdefined( rule, "policy" ) :
                            for src in rules[ direction ][ destination ][ application ][ "sources" ]:
                                if source != "any" and not isdefined( objects2add[ src ], "object" ):
                                        objects.append( ",".join( objects2add[ src ] ) )

                            if not isdefined( objects2add[ destination ], "object" ):
                                    objects.append( ",".join( objects2add[ destination ] ) )
                            inrules.append( ",".join( rule ) )

                            i+=1
                        else:
                            print "skypped:" + line
    i=0
    direction = "outgoing"
    if len( rules[direction] ) > 0:
        for source in rules[ direction ]:
            if len( rules[ direction ][ source ] ) > 0:
                for application in rules[ direction ][ source ]:
                    if len( rules[ direction ][ source ][ application ][ "destinations" ] ) > 0:
                        #if len( rules[ direction ][ source ][ application ][ "destinations" ] ) > 10:
                        #    destination = "any"
                        #else:
                        destination = " ".join( rules[ direction ][ source ][ application ][ "destinations" ] )

                        port = rules[ direction ][ source ][ application ][ "port" ]
                        proto = rules[ direction ][ source ][ application ][ "proto" ]

                        app = False
                        if port+"/"+proto in cpservices:
                            if cpservices[ port+"/"+proto ]["srcport"] == "":
                                #There is no src port so the service is defined in CP
                                app = cpservices[ port+"/"+proto ]["name"]
                            elif cpservices[ port+"/"+proto ]["srcport"] == srcport:
                                #There is srcport and is the same as the rule
                                #so the service is defined in CP
                                app = cpservices[ port+"/"+proto ]["name"]
                        else:
                            app = getspecialapplication( proto, port )

                        if not app:
                            if not isdefined( [ proto + "_" + port, proto, "1-65535", port ], "application" ) :
                                #The service is not defined in CP, we should add it
                                applications.append( ",".join( [ "imp_" + proto + "_" + port, proto, "1-65535", port ] ) )
                            app = "imp_" + proto + "_" + port
                        
                        #if len ( rules[ direction ][ source ] ) > 10:
                        #    application = "any"

                        name = direction + str(i)
                        rule = [ name,action,log,source,destination,app,disabled ]
                        if not isdefined( rule, "policy" ) :
                            if not isdefined( objects2add[ source ], "object" ):
                                    objects.append( ",".join( objects2add[ source ] ) )
                            
                            for dst in rules[ direction ][ source ][ application ][ "destinations" ]:
                                if destination != "any" and not isdefined( objects2add[ dst ], "object" ):
                                        objects.append( ",".join( objects2add[ dst ] ) )
                            
                            outrules.append( ",".join( rule ) )
                            i+=1
                        else:
                            print "skypped:" + line

    writecsv( fileobjects, "Type,Name,Address,Netmask,Description", objects )
    writecsv( "in-"+filerules, "Name,Action,Log,Source,Destination,Application,Disabled", inrules )
    writecsv( "out-"+filerules, "Name,Action,Log,Source,Destination,Application,Disabled", outrules )
    writecsv( fileapplications, "Name,Protocol,Srcport,Dstport", applications )

    writecsv( "historic-"+fileobjects, "Type,Name,Address,Netmask,Description", historicobjects )
    writecsv( "historic-"+filerules, "Action,Log,Source,Destination,Application,Disabled", historicpolicies )
    writecsv( "historic-"+fileapplications, "Name,Protocol,Srcport,Dstport", historicapplications )
    print "Objects added: " + str( len( objects ) )
    print "Applications added: " + str( len( applications ) )
    print "Policies added: " + str( len( inrules ) + len( outrules ) )

loadhistoric()
getcpservices()
getconnections( "rule-permit_all.2016-05-06.csv" )
