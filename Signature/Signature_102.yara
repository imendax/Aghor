rule signature_102
{
	meta:
		author = "0xlsd"
		sample = "e654600fe62082d0b0accb87990c1d53580db024178baaa31ae8fe22a8ee9a38"
	
	
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
			10 58 ??
			65 54
			39 DB
			36 54
			39 DB
		}
	
	condition:
		any of them
	
}
