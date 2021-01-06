rule signature_85
{
	meta:
		author = "0xlsd"
		sample = "9199ebb3c7a9bd63966af8a0100945f2a2ccc8308fb65e08d65cf21027d5b201"
	
	
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
			3D 00 7B DE 79
			61
			15 8D 79 61 15
		}
	
	condition:
		any of them
	
}
