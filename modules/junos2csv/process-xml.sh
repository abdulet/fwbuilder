#!/bin/sh
xmllint --xpath 'configuration/security/nat' backupfw.xml > xml/nat.xml
echo "<policies>\n" > xml/policies.xml
xmllint --xpath 'configuration/security/policies/policy/policy' backupfw.xml >> xml/policies.xml
echo "</policies>\n" >> xml/policies.xml
xmllint --xpath 'configuration/security/zones' backupfw.xml > xml/zones.xml
xmllint --xpath 'configuration/security' backupfw.xml > xml/security-all.xml
xmllint --xpath 'configuration/firewall' backupfw.xml > xml/firewall.xml
xmllint --xpath 'configuration/applications' backupfw.xml > xml/applications.xml
xmllint --xpath 'configuration/routing-options/static' backupfw.xml > xml/static-routes.xml
xmllint --xpath 'configuration/access' backupfw.xml > xml/users.xml
