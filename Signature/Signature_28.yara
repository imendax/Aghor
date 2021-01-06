rule signature_28
{
	meta:
		author = "0xlsd"
		sample = "fed3826446e6cf50c9a4dd2702cd28c296480dbae67fd4532712b6fbb6ff4d59"
	
	
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
			2B 32
		}
	
	condition:
		any of them
	
}
