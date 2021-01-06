rule signature_19
{
	meta:
		author = "0xlsd"
		sample = "8ebee40c3140bb946e91483ba78a2bab2e44dac779339f60426e3ba3963bafaa"
	
	
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
			4E
		}
	
	condition:
		any of them
	
}
