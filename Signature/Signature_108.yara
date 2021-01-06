rule signature_108
{
	meta:
		author = "0xlsd"
		sample = "c6f586d49fd8f5b3038a9d205c568f81cdc921294c6f08c447859830c831555b"
	
	
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
			72 ??
			77 ??
			36 A3 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
