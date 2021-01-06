rule signature_65
{
	meta:
		author = "0xlsd"
		sample = "82fd58284f68fcecb855a109fa737f2fe9a52e8db645bd16ae107285c4d60216"
	
	
	strings:
		$string_1 = {
			20 64 6F ??
			2E 63 72 ??
			61
			74 ??
			45
			6C
			65 6D
			65 6E
			74 ??
			22 73 ??
			72 ??
			70 ??
			22 29
			3B 0D ?? ?? ?? ??
			72 ??
		}
	
	condition:
		any of them
	
}
