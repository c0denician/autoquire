var analysisFolder = WScript.Arguments(0);
var mansFileName = WScript.Arguments(1);
var fullAuditsPath = WScript.Arguments(2);
var auditsFolder = WScript.Arguments(3);

var isIocExist = false;
if (WScript.Arguments.Length >= 5)
{
	isIocExists = WScript.Arguments(4);
}

var SourceScriptFileName = ".\\MemoryzeAuditScript.xml";
var fso = new ActiveXObject("Scripting.FileSystemObject");
var folder = fso.GetFolder(fullAuditsPath);

// Copy script
var fullTargetFileName = fullAuditsPath + "\\Script.xml";
fso.CopyFile(SourceScriptFileName, fullTargetFileName, true);

// Create .mans file with proper path
var fullMansFileName = analysisFolder + "\\" + mansFileName + ".mans";
var f = fso.CreateTextFile(fullMansFileName, true);
f.WriteLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
f.WriteLine("<Root>");
f.WriteLine("\t<AuditPath>" + auditsFolder + "</AuditPath>");
if (isIocExists.toUpperCase() == "TRUE")
{
	f.WriteLine("\t<IocPath>..\\..\\IOCs</IocPath>");
}
f.WriteLine("</Root>");
f.Close();