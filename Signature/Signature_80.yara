rule signature_80
{
	meta:
		author = "0xlsd"
		sample = "1a03571d7dd5a79f7e16b7a8030237aa06e103bfc83f5fd92a28fbbb0516dbf5"
	
	
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
			C2 1E 94
			BF 86 7F FA EC
			86 7F ??
			EC
		}
	
	condition:
		any of them
	
}
