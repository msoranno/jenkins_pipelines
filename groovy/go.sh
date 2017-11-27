#!/bin/bash

#---------------------------------------------------------------------------------------------
# - Este script lanza scripts groovy usando la consola
#   de jenkins y su API
# - Recibe como parámetro el nombre del script groovy
# - Hay 3 variables modificables en el script
# 	- v_user  -> usuario jenkins
#	- v_token -> token del usuario jenkins (puede verse por la interfaz de jenkins)
# 	- jenk_ip -> dns/ip de jenkins
#---------------------------------------------------------------------------------------------

if [ $# -eq 1 ]; then
	v_script="$1"
	# Lo hemos visto desde la interfaz en la config del usuario
	v_user="admin"
	v_token="0cb71b475599b053b593a8f531d052e6"
	jenk_ip="172.50.13.91:8000"

	#Obtenemos el Crumb
	CRUMB=$(curl -s "http://$v_user:$v_token@$jenk_ip/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")
	echo
	echo "---------------------------------------------------------------------------"
	echo "CRUMB ($v_user) -> $CRUMB"
	echo "---------------------------------------------------------------------------"
	echo
	#Ejecución del script
	if [ -f $v_script ]; then
		curl --data-urlencode "script=$(<$v_script)"  -H "$CRUMB" "http://$v_user:$v_token@$jenk_ip/scriptText"
	else
		echo 
		echo "Error: File $v_script not found"
		echo
	fi

else
	echo 
	echo "Error: Missing groovy file."
	echo
fi

