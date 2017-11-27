
/* 
1) Si los plugins role-strategy y ownership no existen
	el script termina. Deben existir ambos antes de ejecutar este script.
2) Este script no contempla la seguridad usada, LDAP, jenkins-database, etc
	esa seguridad deberá ser proporcionada antes.
3) Roles definidos:
	- Ver sección (S-Globales_Def)

*/ 

import hudson.security.*
import com.michelin.cio.hudson.plugins.rolestrategy.*
import java.lang.reflect.*
//import groovy.json.*
//import hudson.*
//import jenkins.model.*
//import java.util.*
//import java.util.logging.*

def jenkInstance = Jenkins.getInstance()
def txtGlobalRole = "Global Role creation"
def txtProjectlRole = "Project Role creation"
def txtPermission = "Selecting permission for"


def getCurrentSecurity(j) {
	def currentAuthStrategy = j.getAuthorizationStrategy()
	def secu = j.getSecurityRealm()
	println	"[-info-] Current strategy: " + currentAuthStrategy
	println	"[-info-] Current security: " + secu
}

/*---------------------------------------------------------
S-Plugin_Validation
Validación de los plugins necesarios
---------------------------------------------------------*/
//Listado de plugins
def list_plugin = ["role-strategy", "ownership"]
def totValida = list_plugin.size()
def plug_ok = 0
for (plug_in in list_plugin) {
	if ( jenkInstance.pluginManager.activePlugins.find { it.shortName == (plug_in) } != null ){
		plug_ok += 1
		println "[-info-] Plugin " + (plug_in) + " found...OK"
	} else {
		println "[-info-] Plugin " + (plug_in) + " NOT found.. :("
	}
}

// validar el contador
if (plug_ok==totValida) {
    println "[-info-] Go..."
} else {
    println "Error: Falta algun plugin"
    return
}

/*---------------------------------------------------------
S-json_Validation
-----------------------------------------------------------*/
/*
def filePath = "./user_roles.json"
def file = new File(filePath)
def pathpwd = new File(System.getProperty("user.dir")).name
println (pathpwd)
try {
	assert file.exists() : "file not found"
	assert file.canRead() : "file cannot be read"
} catch (AssertionError e) {
	println "Error: El fichero ${filePath} no pudo ser leído -- " + e.getMessage()
	return
}
*/
/*---------------------------------------------------------
S-Role_based_on
Se activa la estrategia del Role-based
---------------------------------------------------------*/

//obtenemos la configuracion actual
getCurrentSecurity(jenkInstance)

// Cambiamos a Role-based
println "[-info-] Cambiamos la estrategia al Role-based"
def roleBasedAuthenticationStrategy = new RoleBasedAuthorizationStrategy()
jenkInstance.setAuthorizationStrategy(roleBasedAuthenticationStrategy)

//obtenemos la configuracion actual
getCurrentSecurity(jenkInstance)


/*--------------------------------------------------------------------------------------------
S-Users_Groups_Def
 - Usuarios y grupos
 - Esta es la sección "modificable" cada Key representa un Role Global o Role de Proyecto, y los valores de cada key
   los usuarios a los que se asignará esos roles.
 - Todos los Roles deben ser creados previamente en las secciones posteriores.

tjimenez - Toni Gimenez
ranglada - Robert Anglada
foliveira - Fabio Oliveira
arodriguez - Alexandre Rodriguez Valdes
pdiaz - Pablo Diaz
--------------------------------------------------------------------------------------------*/

//-------------------
//Change Here
//------------------
def access = [
  admins: ["admin", "ranglada", "foliveira", "msoranno", "hmtorres"],
  jobAdmins: ["pdiaz"],
  jobViewers: ["tjimenez", "arodriguez"],
  jobExecutors: ["arodriguez"],
  deployWebsphereBuilder_DEV: ["tjimenez"],
  deployWebsphereBuilder_INT: ["arodriguez"],
  deployWebsphereBuilder_PRO: ["arodriguez"],
  deployWebsphereConfigure_DEV: [],
  deployWebsphereConfigure_INT: [],
  deployWebsphereConfigure_PRO: []
]


//Do not change This
def ownershipAccess = [
  ownerhip_CurrentUserIsPrimaryOwner: ["authenticated"],
  ownerhip_CurrentUserIsOwner: ["authenticated"],
  ownerhip_ItemSpecificWithUserID: ["authenticated"]
]

/*--------------------------------------------------------------------------------------------
S-Globales_Def
Roles Globales:
Cada nuevo role definido aquí requiere agregar nuevos elementos en las secciones:
- S-Permissions_Def
- S-Roles_Permission_Set
- S-Users_Groups_Set
--------------------------------------------------------------------------------------------*/
def globalRoleAdmin  = "admin"
def globalJobAdmin   = "job-admin"
def globalJobViewer  = "job-viewer"
def globalRegistered = "registered"
def globalJobExecu   = "job-executor"


/*---------------------------------------------------------------------------------------------
S-ProjectRoles_Def
Roles por proyectos y sus respectivos patrones
-----------------------------------------------------------------------------------------------*/

/*********** deployWebsphereBuilder **********/
//DEV
def deployWebsphereBuilder_RoleName_DEV = "CA_CIS_DeployWebsphere_Builder_DEV"
def deployWebsphereBuilder_Pattern_DEV = 'CA_CIS_DeployWebsphere.*_DEV'
//INT
def deployWebsphereBuilder_RoleName_INT = "CA_CIS_DeployWebsphere_Builder_INT"
def deployWebsphereBuilder_Pattern_INT = 'CA_CIS_DeployWebsphere.*_INT'
//PRO
def deployWebsphereBuilder_RoleName_PRO = "CA_CIS_DeployWebsphere_Builder_PRO"
def deployWebsphereBuilder_Pattern_PRO = 'CA_CIS_DeployWebsphere.*_PRO'

/*********** deployWebsphereConfigure **********/
//DEV
def deployWebsphereConfigure_RoleName_DEV = "CA_CIS_DeployWebsphere_Configure_DEV"
def deployWebsphereConfigure_Pattern_DEV = 'CA_CIS_DeployWebsphere.*_DEV'
//INT
def deployWebsphereConfigure_RoleName_INT = "CA_CIS_DeployWebsphere_Configure_INT"
def deployWebsphereConfigure_Pattern_INT = 'CA_CIS_DeployWebsphere.*_INT'
//PRO
def deployWebsphereConfigure_RoleName_PRO = "CA_CIS_DeployWebsphere_Configure_PRO"
def deployWebsphereConfigure_Pattern_PRO = 'CA_CIS_DeployWebsphere.*_PRO'

/*********** Ownership plugin special **********/
def ownerhip_CurrentUserIsPrimaryOwner = '@CurrentUserIsPrimaryOwner'
def ownerhip_CurrentUserIsOwner = '@CurrentUserIsOwner'
def ownerhip_ItemSpecificWithUserID = '@ItemSpecificWithUserID'
def ownership_pattern = '.*'

/*--------------------------------------------------------------------------------------------
S-Permissions_Def
Grupo Permisos Administrativos. Como si clicaramos por la interfaz
Aqui se definen los permisos asociados a los roles
---------------------------------------------------------------------------------------------*/

//CurrentUserIsPrimaryOwner
def oShip_CurrentUserIsPrimaryOwnerPermission = [
"com.synopsys.arc.jenkins.plugins.ownership.OwnershipPlugin.Jobs",
"hudson.model.Run.Replay",
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

//CurrentUserIsOwner
def oShip_CurrentUserIsOwnerPermission = [
"hudson.model.Item.Configure",
"hudson.model.Item.Cancel",
"hudson.model.Item.Read",
"hudson.model.Item.Build",
"hudson.model.Item.ExtendedRead",
"hudson.model.Item.Move",
"hudson.model.Item.Discover",
"hudson.model.Item.Workspace",
"hudson.model.Item.WipeOut"
]

//ItemSpecificWithUserID
def oShip_ItemSpecificWithUserIDPermission = [
"hudson.model.Item.Configure",
"hudson.model.Item.Cancel",
"hudson.model.Item.Read",
"hudson.model.Item.Build",
"hudson.model.Item.ExtendedRead",
"hudson.model.Item.Move",
"hudson.model.Item.Discover",
"hudson.model.Item.Workspace",
"hudson.model.Item.WipeOut"
]


//deployWebsphereBuilder
def deployWebsphereBuilder_Permission = [
"hudson.model.Run.Replay",
"hudson.model.Item.Build"
]

//deployWebsphereConfigure
def deployWebsphereConfigure_Permission = [
"hudson.model.Run.Replay",
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

//registered
def registeredPermissions = [
"hudson.model.Hudson.Read",
"hudson.model.View.Read"
]

//job-executor
def job_executorPermissions = [
"hudson.model.Hudson.Read",
"hudson.model.View.Read",
"hudson.model.Run.Replay",
"hudson.model.Run.Artifacts",
"hudson.model.Run.Update",
"hudson.model.Item.Cancel",
"hudson.model.Item.Read",
"hudson.model.Item.Build",
"hudson.model.Item.ExtendedRead",
"hudson.model.Item.Discover",
"hudson.model.Item.Workspace"
]

//job-viewer
def job_viewerPermissions = [
"hudson.model.Hudson.Read",
"hudson.model.View.Read",
"hudson.model.Item.Read",
"hudson.model.Item.Discover",
"hudson.model.Item.Workspace"
]

//job-admin
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

//admin
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

// Damos accesibilidad al metodo assignRole (Investigar)
Method assignRoleMethod = RoleBasedAuthorizationStrategy.class.getDeclaredMethod("assignRole", String.class, Role.class, String.class);
assignRoleMethod.setAccessible(true);


/*--------------------------------------------------------------
S-Permissions_Set
Creamos un grupo de permisos (Clickamos)
--------------------------------------------------------------*/

//admin
println "[-info-] ${txtPermission} ${globalRoleAdmin} "
Set<Permission> adminPermissionSet = new HashSet<Permission>();
adminPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    adminPermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//job-admin
println "[-info-] ${txtPermission} ${globalJobAdmin} "
Set<Permission> job_adminPermissionsSet = new HashSet<Permission>();
job_adminPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    job_adminPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//job-viewer
println "[-info-] ${txtPermission} ${globalJobViewer}"
Set<Permission> job_viewerPermissionsSet = new HashSet<Permission>();
job_viewerPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    job_viewerPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}


//job-executor
println "[-info-] ${txtPermission} ${globalJobExecu}"
Set<Permission> job_executorPermissionsSet = new HashSet<Permission>();
job_executorPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    job_executorPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}


//registered
println "[-info-] ${txtPermission} ${globalRegistered}"
Set<Permission> registeredPermissionsSet = new HashSet<Permission>();
registeredPermissions.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    registeredPermissionsSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//deployWebsphereBuilder_RoleName (DEV,INT,PRO)
//Se usa el mismo set de permisos para los 3 entornos.
println "[-info-] ${txtPermission} ${deployWebsphereBuilder_RoleName_DEV}"
println "[-info-] ${txtPermission} ${deployWebsphereBuilder_RoleName_INT}"
println "[-info-] ${txtPermission} ${deployWebsphereBuilder_RoleName_PRO}"
Set<Permission> deployWebsphereBuilder_PermissionSet = new HashSet<Permission>();
deployWebsphereBuilder_Permission.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    deployWebsphereBuilder_PermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//deployWebsphereConfigure_RoleName (DEV,INT,PRO)
//Se usa el mismo set de permisos para los 3 entornos.
println "[-info-] ${txtPermission} ${deployWebsphereConfigure_RoleName_DEV}"
println "[-info-] ${txtPermission} ${deployWebsphereConfigure_RoleName_INT}"
println "[-info-] ${txtPermission} ${deployWebsphereConfigure_RoleName_PRO}"
Set<Permission> deployWebsphereConfigure_PermissionSet = new HashSet<Permission>();
deployWebsphereConfigure_Permission.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    deployWebsphereConfigure_PermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//Ownership - CurrentUserIsPrimaryOwnerPermission
Set<Permission> oShip_CurrentUserIsPrimaryOwnerPermissionSet = new HashSet<Permission>();
oShip_CurrentUserIsPrimaryOwnerPermission.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    oShip_CurrentUserIsPrimaryOwnerPermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//Ownership - CurrentUserIsOwnerPermission
Set<Permission> oShip_CurrentUserIsOwnerPermissionSet = new HashSet<Permission>();
oShip_CurrentUserIsOwnerPermission.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    oShip_CurrentUserIsOwnerPermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}

//Ownership - ItemSpecificWithUserIDPermission
Set<Permission> oShip_ItemSpecificWithUserIDPermissionSet = new HashSet<Permission>();
oShip_ItemSpecificWithUserIDPermission.each { p ->
  def permission = Permission.fromId(p);
  if (permission != null) {
    oShip_ItemSpecificWithUserIDPermissionSet.add(permission);
  } else {
    println("Error: ${p} No es un permiso valido (Ignoramos)")
  }
}


/*--------------------------------------------------------------
S-Roles_Permission_Set
Creamos los roles globales junto con los grupos clickeados
--------------------------------------------------------------*/


// admins
println "[-info-] ${txtGlobalRole} ${globalRoleAdmin}"
Role adminRole = new Role(globalRoleAdmin, adminPermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, adminRole);

// job-admins
println "[-info-] ${txtGlobalRole} ${globalJobAdmin}"
Role jobAdminRole = new Role(globalJobAdmin, job_adminPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, jobAdminRole);

// job-viewers
println "[-info-] ${txtGlobalRole} ${globalJobViewer}"
Role jobViewerRole = new Role(globalJobViewer, job_viewerPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, jobViewerRole);


// job-executors
println "[-info-] ${txtGlobalRole} ${globalJobExecu}"
Role jobExecuRole = new Role(globalJobExecu, job_executorPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, jobExecuRole);


// registered
println "[-info-] ${txtGlobalRole} ${globalRegistered}"
Role registeredRole = new Role(globalRegistered, registeredPermissionsSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.GLOBAL, registeredRole);


/*--------------------------------------------------------------
S-ProjectRoles_Permission_Set
Creamos los roles de proyectos junto con los grupos clickeados
--------------------------------------------------------------*/

//Builders
println "[-info-] ${txtProjectlRole} ${deployWebsphereBuilder_RoleName_DEV}"
Role deployWebsphere_Builder_DEV = new Role(deployWebsphereBuilder_RoleName_DEV,deployWebsphereBuilder_Pattern_DEV,deployWebsphereBuilder_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Builder_DEV);

println "[-info-] ${txtProjectlRole} ${deployWebsphereBuilder_RoleName_INT}"
Role deployWebsphere_Builder_INT = new Role(deployWebsphereBuilder_RoleName_INT,deployWebsphereBuilder_Pattern_INT,deployWebsphereBuilder_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Builder_INT);

println "[-info-] ${txtProjectlRole} ${deployWebsphereBuilder_RoleName_PRO}"
Role deployWebsphere_Builder_PRO = new Role(deployWebsphereBuilder_RoleName_PRO,deployWebsphereBuilder_Pattern_PRO,deployWebsphereBuilder_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Builder_PRO);

//Configure
println "[-info-] ${txtProjectlRole} ${deployWebsphereConfigure_RoleName_DEV}"
Role deployWebsphere_Configure_DEV = new Role(deployWebsphereConfigure_RoleName_DEV,deployWebsphereConfigure_Pattern_DEV,deployWebsphereConfigure_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Configure_DEV);

println "[-info-] ${txtProjectlRole} ${deployWebsphereConfigure_RoleName_INT}"
Role deployWebsphere_Configure_INT = new Role(deployWebsphereConfigure_RoleName_INT,deployWebsphereConfigure_Pattern_INT,deployWebsphereConfigure_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Configure_INT);

println "[-info-] ${txtProjectlRole} ${deployWebsphereConfigure_RoleName_PRO}"
Role deployWebsphere_Configure_PRO = new Role(deployWebsphereConfigure_RoleName_PRO,deployWebsphereConfigure_Pattern_PRO,deployWebsphereConfigure_PermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,deployWebsphere_Configure_PRO);

//------------------ ownership--------------//
//ownership- CurrentUserIsPrimaryOwner
println "[-info-] ${txtProjectlRole} ${ownerhip_CurrentUserIsPrimaryOwner}"
Role ownerhip_CurrentUserIsPrimaryOwner_Role = new Role(ownerhip_CurrentUserIsPrimaryOwner,ownership_pattern,oShip_CurrentUserIsPrimaryOwnerPermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,ownerhip_CurrentUserIsPrimaryOwner_Role);

//ownership- CurrentUserIsOwner
println "[-info-] ${txtProjectlRole} ${ownerhip_CurrentUserIsOwner}"
Role ownerhip_CurrentUserIsOwner_Role = new Role(ownerhip_CurrentUserIsOwner,ownership_pattern,oShip_CurrentUserIsOwnerPermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,ownerhip_CurrentUserIsOwner_Role);

//ownership- CurrentUserIsOwner
println "[-info-] ${txtProjectlRole} ${ownerhip_ItemSpecificWithUserID}"
Role ownerhip_ItemSpecificWithUserID_Role = new Role(ownerhip_ItemSpecificWithUserID,ownership_pattern,oShip_ItemSpecificWithUserIDPermissionSet);
roleBasedAuthenticationStrategy.addRole(RoleBasedAuthorizationStrategy.PROJECT,ownerhip_ItemSpecificWithUserID_Role);


/*--------------------------------------------------------------
S-Users_Groups_Set
Aqui se asocian los usuarios y/o grupos a los respectivos roles
--------------------------------------------------------------*/

println "------------------------------------"
println "Granting users/groups to Roles"
println "------------------------------------"

//registered
//No aplica.

//Admin
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
//job-executor
access.jobExecutors.each { usuario ->
  println("[-info-] Granting ${globalJobExecu} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.GLOBAL, jobExecuRole, usuario);  
}

//---------deployWebsphereBuilder---------//
//deployWebsphereBuilder_DEV
access.deployWebsphereBuilder_DEV.each { usuario ->
  println("[-info-] Granting ${deployWebsphereBuilder_RoleName_DEV} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Builder_DEV, usuario);  
}
//deployWebsphereBuilder_INT
access.deployWebsphereBuilder_INT.each { usuario ->
  println("[-info-] Granting ${deployWebsphereBuilder_RoleName_INT} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Builder_INT, usuario);  
}
//deployWebsphereBuilder_PRO
access.deployWebsphereBuilder_PRO.each { usuario ->
  println("[-info-] Granting ${deployWebsphereBuilder_RoleName_PRO} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Builder_PRO, usuario);  
}

//---------deployWebsphereConfigure---------//
//deployWebsphereConfigure_DEV
access.deployWebsphereConfigure_DEV.each { usuario ->
  println("[-info-] Granting ${deployWebsphereConfigure_RoleName_DEV} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Configure_DEV, usuario);  
}
//deployWebsphereConfigure_INT
access.deployWebsphereConfigure_INT.each { usuario ->
  println("[-info-] Granting ${deployWebsphereConfigure_RoleName_INT} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Configure_INT, usuario);  
}
//deployWebsphereConfigure_PRO
access.deployWebsphereConfigure_PRO.each { usuario ->
  println("[-info-] Granting ${deployWebsphereConfigure_RoleName_PRO} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, deployWebsphere_Configure_PRO, usuario);  
}

//-------------Ownership----------------//
//CurrentUserIsPrimaryOwner
ownershipAccess.ownerhip_CurrentUserIsPrimaryOwner.each { usuario ->
  println("[-info-] Granting ${ownerhip_CurrentUserIsPrimaryOwner} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, ownerhip_CurrentUserIsPrimaryOwner_Role, usuario);  
}
//CurrentUserIsOwner
ownershipAccess.ownerhip_CurrentUserIsOwner.each { usuario ->
  println("[-info-] Granting ${ownerhip_CurrentUserIsOwner} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, ownerhip_CurrentUserIsOwner_Role, usuario);  
}
//ItemSpecificWithUserID
ownershipAccess.ownerhip_ItemSpecificWithUserID.each { usuario ->
  println("[-info-] Granting ${ownerhip_ItemSpecificWithUserID} to ${usuario}")
  roleBasedAuthenticationStrategy.assignRole(RoleBasedAuthorizationStrategy.PROJECT, ownerhip_ItemSpecificWithUserID_Role, usuario);  
}

/*-------------------------------------
// Si falta un plugin no deberia llegar a esta
-------------------------------------*/
println	"End Save"
jenkInstance.save()