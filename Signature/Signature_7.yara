rule signature_7
{
	meta:
		author = "0xlsd"
		sample = "3e8ff58bd916c0a6bb86083a566b61be4f0e45ec1aceb211cde19f79c23b9ae0"
	
	
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
			5D
		}
	
	condition:
		any of them
	
}
