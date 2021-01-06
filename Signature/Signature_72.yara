rule signature_72
{
	meta:
		author = "0xlsd"
		sample = "ca2237b51a87a0d6143eda5f576b2c160add06cffaacf73a58908aad66033fca"
	
	
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
			80 EE 81
			0E
			C4 8F ?? ?? ?? ??
			EF
			5D
		}
	
	condition:
		any of them
	
}
