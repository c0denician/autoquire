var sessionsFolder = WScript.Arguments(0);
var analysisFolderName = WScript.Arguments(1);

//WScript.Echo ("Param 0: " + sessionsFolder);
//WScript.Echo ("Param 1: " + analysisFolderName);

var fso = new ActiveXObject("Scripting.FileSystemObject");
var folder = fso.GetFolder(sessionsFolder);
var colSubfolders = new Enumerator(folder.SubFolders);

var lastUsedNumber = 0;
for (; !colSubfolders.atEnd(); colSubfolders.moveNext())
{
	if (colSubfolders.item().Name.toUpperCase().indexOf(analysisFolderName.toUpperCase()) != -1)
	{
		var number = parseInt(colSubfolders.item().Name.substring(analysisFolderName.length));
		if (number > lastUsedNumber)
		{
			lastUsedNumber = number;
		}
	}
}
//WScript.Echo ("Next session number is " + (lastUsedNumber + 1));
WScript.Echo (analysisFolderName + (lastUsedNumber + 1));
