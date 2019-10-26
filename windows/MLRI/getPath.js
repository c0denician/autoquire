var HKLM = 0x80000002; 
var HKLM_text = "HKEY_LOCAL_MACHINE";
var Name = "\\DisplayName";
var Location = "\\InstallLocation";
var agentNames = new Array("xagt", "FireEye Endpoint Agent");
var regKeyPath = new Array(
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 
	"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

var ret = "";

if (WScript.Arguments.Length >= 1)
{
	ret = WScript.Arguments(0);
}

for (var i = 0; i < regKeyPath.length; ++i)
{
	if (isInstalled(regKeyPath[i]))
	{
		break;
	}
}

if (ret.lastIndexOf("\\") != (ret.length - 1))
{
	ret = ret.concat("\\");
}
WScript.Echo(ret); 
 
//-----
function isInstalled(path)
{ 
    var found = false;
	var rtn = regGetSubKeys(".", path) 
	if ( rtn.Results == 0 ) 
	{ 
	  var objShell = WScript.CreateObject("WScript.Shell");
	  var subKeyValue;
	  for (var idx=0;idx<rtn.SubKeys.length;idx++) 
	  { 
		var exists = true;
		var fullKeyName = HKLM_text + "\\" + path + "\\" + rtn.SubKeys[idx];
		try
		{
			subKeyValue = objShell.RegRead(fullKeyName + Name);
			for (var i = 0; i < agentNames.length; ++i)
			{
				if (subKeyValue == agentNames[i])
				{
					ret = objShell.RegRead(fullKeyName + Location);
					found = true;
					break;
				}
			}
		}
		catch (e) {
			exists = false;
		}
		if (found)
			break;
	  } 
	}
	return found;
} 
 

//------------------------------------------------------------- 
// function : regGetSubKeyNames(strComputer, strRegPath) 
// Based upon https://gallery.technet.microsoft.com/scriptcenter/Simple-JScriptJavascript-2a46ed8b#content
//  purpose : return an array with names of any subKeys 
//------------------------------------------------------------- 
function regGetSubKeys(strComputer, strRegPath) 
{ 
    var aNames = null; 
    var objLocator     = new ActiveXObject("WbemScripting.SWbemLocator"); 
    var objService     = objLocator.ConnectServer(strComputer, "root\\default"); 
    var objReg         = objService.Get("StdRegProv"); 
    var objMethod      = objReg.Methods_.Item("EnumKey"); 
    var objInParam     = objMethod.InParameters.SpawnInstance_(); 
    objInParam.hDefKey = HKLM; 
    objInParam.sSubKeyName = strRegPath; 
    var objOutParam = objReg.ExecMethod_(objMethod.Name, objInParam); 
    if (objOutParam.ReturnValue == 0)   // Success 
    { 
        aNames = (objOutParam.sNames != null) ? objOutParam.sNames.toArray(): null; 
    } 
    return { Results : objOutParam.ReturnValue, SubKeys : aNames }; 
}