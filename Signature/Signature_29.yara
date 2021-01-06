rule signature_29
{
	meta:
		author = "0xlsd"
		sample = "24b799dfe6978403981bca2ce5211b452b3b554213e9a7200cb33609111d2274"
	
	
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
			19 D7
		}
	
	condition:
		any of them
	
}
