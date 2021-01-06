rule signature_6
{
	meta:
		author = "0xlsd"
		sample = "1082071060436012cc14b47849d47efc1c620f7b43c0e9d865b467ad9f0ad34b"
	
	
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
