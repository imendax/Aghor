rule signature_14
{
	meta:
		author = "0xlsd"
		sample = "24cd48ed94427ec8e2b03b621ba36b785189cc6336749f286034f43cfea1e8d8"
	
	
	strings:
		$string_1 = {
			6C
			31 2D ?? ?? ?? ??
			73 ??
			74 ??
			6F
			6E
			61
			6C
			2E 64 74 ??
			22 3E
			0D 0A 3C 68 74
			6D
			6C
		}
	
	condition:
		any of them
	
}
