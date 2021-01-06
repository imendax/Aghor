rule signature_95
{
	meta:
		author = "0xlsd"
		sample = "621510744ec8b7f620717abc933f0b34b5be1d0c011964837fde7be70b5f1d98"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 75 ??
			64 65 72 ??
			57
			69 6E ?? 32 0A 0D 24
			37
			00 00
			00 00
			00 00
			00 00
			50
			45
			00 00
			4C
			01 04 00
			FD
			AE
			44
			44
		}
	
	condition:
		any of them
	
}
