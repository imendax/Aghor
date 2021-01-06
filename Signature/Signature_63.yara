rule signature_63
{
	meta:
		author = "0xlsd"
		sample = "22b52590a7fa5ca27f2c4662f6a64374c4489180aca4e039ebdff5de0d4de83b"
	
	
	strings:
		$string_1 = {
			74 ??
			58
			BA EA BE 4D 27
			74 ??
			58
			BA DE BE 19 27
			74 ??
			4A
			5F
			E7 BE
			4E
			27
			74 ??
			43
			27
			75 ??
			32 27
			74 ??
			58
			BA DB BE 42 27
		}
	
	condition:
		any of them
	
}
