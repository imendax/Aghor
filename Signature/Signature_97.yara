rule signature_97
{
	meta:
		author = "0xlsd"
		sample = "ccb3022b688f26bcfc9be5c15519c563f1517039ea271e8258bde62845b2c83f"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			77 ??
			C9
			38 33
			05 A7 6B 33 05
			A7
		}
	
	condition:
		any of them
	
}
