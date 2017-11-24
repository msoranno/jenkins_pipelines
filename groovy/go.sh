#!/bin/bash

#----------------------------------------------------
# Este script lanza scripts groovy usando la consola
# de jenkins y su API
#
#-----------------------------------------------------

v_script="$1"
# Lo hemos visto desde la interfaz en la config del usuario
v_token="0cb71b475599b053b593a8f531d052e6"
v_user="admin"
jenk_ip="172.50.13.91:8000"

#Obtenemos el Crumb
CRUMB=$(curl -s "http://$v_user:$v_token@$jenk_ip/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")
echo
echo "---------------------------------------------------------------------------"
echo "CRUMB -> $CRUMB"
echo "---------------------------------------------------------------------------"
echo
#Ejecución del script
curl --data-urlencode "script=$(<./$v_script)"  -H "$CRUMB" "http://$v_user:$v_token@$jenk_ip/scriptText"

