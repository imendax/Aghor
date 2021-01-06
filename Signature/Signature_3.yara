rule signature_3
{
	meta:
		author = "0xlsd"
		sample = "edde1e3c5c1fd95befc6fb84714ae5d1e73af95269e4f94bc29d1a0721b807c9"
	
	
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
