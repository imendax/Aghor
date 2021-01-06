rule signature_26
{
	meta:
		author = "0xlsd"
		sample = "76c862ef2688e728ab704194d783bcf09b65fc46b285f693e4f509d1e78f2c3e"
	
	
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
			93
			A6
		}
	
	condition:
		any of them
	
}
