rule signature_98
{
	meta:
		author = "0xlsd"
		sample = "36f5a1de5abd4ae747763209005c0538df48cb0d1cbf010da9547bab66c0cf43"
	
	
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
			AD
			62 29
			A0 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
