rule signature_67
{
	meta:
		author = "0xlsd"
		sample = "7a1bdb83714d8ca9108a8055c73b87e7fd9258ac07003e8470a3bbdd9cdb1706"
	
	
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
			BD 31 6D FE F9
			50
			03 AD ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
