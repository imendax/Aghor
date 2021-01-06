rule signature_12
{
	meta:
		author = "0xlsd"
		sample = "b1cf26c150622b2a0f2e22ee3e9122fb38c7b12170375a3711b8773452409aa8"
	
	
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
