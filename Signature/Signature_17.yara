rule signature_17
{
	meta:
		author = "0xlsd"
		sample = "98ecea54bce4b9b85a074ded4fd84aa6221fb1410b4d6eba359a62c49df176a0"
	
	
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
			50
			45
		}
	
	condition:
		any of them
	
}
