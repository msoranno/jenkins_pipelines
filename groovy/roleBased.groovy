
/* 
1) Si los plugins role-strategy y ownership no existen
	el script termina. Deben existir ambos!
2) Este script no contempla la seguridad usada, LDAP, jenkins-database, etc
	esa seguridad deberá ser proporcionada antes.
*/ 
//import hudson.*
import hudson.security.*
//import jenkins.model.*
//import java.util.*
import com.michelin.cio.hudson.plugins.rolestrategy.*
import java.lang.reflect.*
//import java.util.logging.*
//import groovy.json.*

def jenkInstance = Jenkins.getInstance()


def getCurrentSecurity(j) {
	def currentAuthStrategy = j.getAuthorizationStrategy()
	def secu = j.getSecurityRealm()
	println	"[-info-] Tipo de estrategia actual: " + currentAuthStrategy
	println	"[-info-] Tipo de seguridad actual: " + secu
}


def list_plugin = ["role-strategy", "ownership"]
def totValida = list_plugin.size()
def plug_ok = 0
for (plug_in in list_plugin) {
	if ( jenkInstance.pluginManager.activePlugins.find { it.shortName == (plug_in) } != null ){
		plug_ok += 1
		println "[-info-] El plugin " + (plug_in) + " existe...OK"
	} else {
		println "[-info-] El plugin " + (plug_in) + " NO existe.. :("
	}
}

// validar el contador
if (plug_ok==totValida) {
    println "[-info-] Go..."
} else {
    println "Error: Falta algun plugin"
    return
}

//obtenemos la configuracion actual
getCurrentSecurity(jenkInstance)

// Cambiamos a Role-based
println "[-info-] Cambiamos la estrategia al Role-based"
def roleBasedAuthenticationStrategy = new RoleBasedAuthorizationStrategy()
jenkInstance.setAuthorizationStrategy(roleBasedAuthenticationStrategy)

//obtenemos la configuracion actual
getCurrentSecurity(jenkInstance)


/*
--------------------------------------------------------------------------------------------
Roles Globales:
Cada nuevo role definido aquí requiere agregar nuevos elementos en las secciones debajo.
--------------------------------------------------------------------------------------------
*/
def globalRoleAdmin = "admin"
def globalJobAdmin  = "job-admin"
def globalJobExecu  = "job-executor"
def globalJobViewer = "job-viewer"


/*
--------------------------------------------------------------------------------------------
 Usuarios y grupos
 Esta es la sección "modificable" cada Key representa un Role, y los valores de cada key
 los usuarios a los que se asignará esos roles.
--------------------------------------------------------------------------------------------
*/
def access = [
  admins: ["admin", "msorannom"],
  jobAdmins: ["test1"],
  jobViewers: ["test2"],
  jobExecutors: []
]



/*
--------------------------------------------------------------------------------------------
	Grupo Permisos Administrativos. Como si clicaramos por la interfaz
Aqui se definen los permisos asociados a los roles
---------------------------------------------------------------------------------------------
*/

def job_viewerPermissions = [
"hudson.model.Hudson.Read",
"hudson.model.View.Read",
"hudson.model.Item.Read",
"hudson.model.Item.Discover",
"hudson.model.Item.Workspace"
]

def job_adminPermissions = [
"hudson.model.Hudson.Read",
"hudson.model.View.Read",
"hudson.model.View.Create",
"hudson.model.Run.Delete",
"hudson.model.Run.Replay",
"hudson.model.Run.Artifacts",
"hudson.model.Run.Update",
"hudson.model.Item.Configure",
"hudson.model.Item.Cancel",
"hudson.model.Item.Read",
"hudson.model.Item.Build",
"hudson.model.Item.ExtendedRead",
"hudson.model.Item.Move",
"hudson.model.Item.Discover",
"hudson.model.Item.Create",
"hudson.model.Item.Workspace",
"hudson.model.Item.WipeOut",
"hudson.model.Item.Delete"
]

def adminPermissions = [
"hudson.model.View.Delete",
"hudson.model.View.Configure",
"hudson.model.View.Read",
"hudson.model.View.Create",
"hudson.model.Computer.Connect",
"hudson.model.Computer.Create",
"hudson.model.Computer.Build",
"hudson.model.Computer.Delete",
"hudson.model.Computer.Provision",
"hudson.model.Computer.ExtendedRead",
"hudson.model.Computer.Configure",
"hudson.model.Computer.Disconnect",
"hudson.model.Run.Delete",
"hudson.model.Run.Replay",
"hudson.model.Run.Artifacts",
"hudson.model.Run.Update",
"hudson.model.Item.Configure",
"hudson.model.Item.Cancel",
"hudson.model.Item.Read",
"hudson.model.Item.Build",
"hudson.model.Item.ExtendedRead",
"hudson.model.Item.Move",
"hudson.model.Item.Discover",
"hudson.model.Item.Create",
"hudson.model.Item.Workspace",
"hudson.model.Item.WipeOut",
"hudson.model.Item.Delete",
"jenkins.metrics.api.Metrics.View",
"jenkins.metrics.api.Metrics.HealthCheck",
"jenkins.metrics.api.Metrics.ThreadDump",
"com.cloudbees.plugins.credentials.CredentialsProvider.ManageDomains",
"com.cloudbees.plugins.credentials.CredentialsProvider.View",
"com.cloudbees.plugins.credentials.CredentialsProvider.Update",
"com.cloudbees.plugins.credentials.CredentialsProvider.Delete",
"com.cloudbees.plugins.credentials.CredentialsProvider.Create",
"com.cloudbees.plugins.credentials.CredentialsProvider.UseItem",
"com.cloudbees.plugins.credentials.CredentialsProvider.UseOwn",
"hudson.model.Hudson.UploadPlugins",
"hudson.model.Hudson.ConfigureUpdateCenter",
"hudson.model.Hudson.Administer",
"hudson.model.Hudson.Read",
"hudson.model.Hudson.RunScripts",
"com.synopsys.arc.jenkins.plugins.ownership.OwnershipPlugin.Jobs",
"com.synopsys.arc.jenkins.plugins.ownership.OwnershipPlugin.Nodes",
"hudson.scm.SCM.Tag"
]


//-----
// Investigar con la gente de java
//-----
Constructor[] constrs = Role.class.getConstructors();
	for (Constructor<?> c : constrs) {
		c.setAccessible(true);
}

// Damos accesibilidad al metodo assignRole
Method assignRoleMethod = RoleBasedAuthorizationStrategy.class.getDeclaredMethod("assignRole", String.class, Role.class, String.class);
assignRoleMethod.setAccessible(true);


/*
--------------------------------------------------------------
Creamos un grupo de permisos (Clickamos)
--------------------------------------------------------------
*/
println "[-info-] Seleccionamos permisos para administradores "
Set<Permission> adminPermissionSet = new HashSet<Permission>();
adminPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    adminPermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

println "[-info-] Seleccionamos permisos para job-admin "
Set<Permission> job_adminPermissionsSet = new HashSet<Permission>();
job_adminPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    job_adminPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

println "[-info-] Seleccionamos permisos para job-viewer"
Set<Permission> job_viewerPermissionsSet = new HashSet<Permission>();
job_viewerPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    job_viewerPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}



/*
--------------------------------------------------------------
Creamos los roles globales junto con los grupos clickeados
--------------------------------------------------------------
*/


// admins
println "[-info-] Creamos el role ${globalRoleAdmin}"
Role adminRole = new Role(globalRoleAdmin, adminPermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, adminRole);

// job-admins
println "[-info-] Creamos el role ${globalJobAdmin}"
Role jobAdminRole = new Role(globalJobAdmin, job_adminPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, jobAdminRole);

// job-viewers
println "[-info-] Creamos el role ${globalJobViewer}"
Role jobViewerRole = new Role(globalJobViewer, job_viewerPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, jobViewerRole);




/*
--------------------------------------------------------------
Aqui se asocian los usuarios y/o grupos a los respectivos roles
--------------------------------------------------------------
*/

//Admin
println "------------------------------------"
println "Granting users/groups to Roles"
println "------------------------------------"

access.admins.each { usuario ->
  println("[-info-] Granting ${globalRoleAdmin} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.GLOBAL, adminRole, usuario);  
}

//job-admin
access.jobAdmins.each { usuario ->
  println("[-info-] Granting ${globalJobAdmin} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.GLOBAL, jobAdminRole, usuario);  
}

//job-viewer
access.jobViewers.each { usuario ->
  println("[-info-] Granting ${globalJobViewer} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.GLOBAL, jobViewerRole, usuario);  
}




// Si falta un plugin no deberia llegar a esta
println	"Fin Save"
jenkInstance.save()









/* 
Pendiente: Crear Roles de proyectos

ejemplo:
// Create the Role
    Role contentRole = new Role(contentRoleName,contentRolePattern,contentPermissions);
    roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,contentRole);

    https://github.com/Accenture/adop-platform-management/blob/master/projects/groovy/acl_admin.groovy





DOCUMENTACION VARIADA

	//Verificando si el plugin está activo
//def currentAuthStrategy = Hudson.instance.getAuthorizationStrategy()  
	if (currentAuthStrategy instanceof RoleBasedAuthorizationStrategy) {
	      println "Role-based está siendo usado"
	} else {
	      println "Enabling role based authorisation strategy..."
	}

["role-strategy", "ownership"].each {
	if (! pm.getPlugin(it)) {
	  deployment = uc.getPlugin(it).deploy(true)
	  deployment.get()
	}
	activatePlugin(pm.getPlugin(it))
}


//-----------------------------------------------------------
// Procedimiento para agilizar el desarrollo

1. Ver el token de tu usuario. Por la interfaz en la configuración del mismo
	Para mi usuario admin el token es: 
	0cb71b475599b053b593a8f531d052e6
2. Obtenemos el crumb
	2.1 Con usuario y contraseña:
		wget -q --auth-no-challenge --user admin --password admin --output-document - 'http://172.50.13.91:8000/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)'
		devuelve esto:
		Jenkins-Crumb:400c720138d4481fd0763b8e10428ca1
	2.2 Con el token
		CRUMB=$(curl -s 'http://admin:0cb71b475599b053b593a8f531d052e6@172.50.13.91:8000/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)')
		devuelve esto:
		Jenkins-Crumb:400c720138d4481fd0763b8e10428ca1


v_toke="0cb71b475599b053b593a8f531d052e6"
v_user="admin"

CRUMB=$(curl -s 'http://admin:0cb71b475599b053b593a8f531d052e6@172.50.13.91:8000/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)')
curl -d "script=test.groovy" -H "Jenkins-Crumb:400c720138d4481fd0763b8e10428ca1" http://admin:0cb71b475599b053b593a8f531d052e6@172.50.13.91:8000/scriptText

curl -d "script=test.groovy" -H "$CRUMB" http://admin:0cb71b475599b053b593a8f531d052e6@172.50.13.91:8000/scriptText

//--------------------------------------------------------------
*/