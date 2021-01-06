rule signature_112
{
	meta:
		author = "0xlsd"
		sample = "f4c90112ad8d36e6ca4775bd76c1e06c2af5f6458668ab17e410e89c8aa5d607"
	
	
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
			91
			0F 43 D7
			D5 6E
			2D 84 D5 6E 2D
		}
	
	condition:
		any of them
	
}
