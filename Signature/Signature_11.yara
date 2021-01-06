rule signature_11
{
	meta:
		author = "0xlsd"
		sample = "d5c1e1da68c59278502236094cc5538e06ec12a9ad50a5f0c608686af86a6f8d"
	
	
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
			D6
		}
	
	condition:
		any of them
	
}
