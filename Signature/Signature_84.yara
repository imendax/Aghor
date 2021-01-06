rule signature_84
{
	meta:
		author = "0xlsd"
		sample = "dc79dc3344bd02c4eb9f6df0dfda08c28212451f526d8a3ec8bd3374befe92f9"
	
	
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
			00 00
			4C
			01 02
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
